package ruby

var template = `# Code generated by Avian; DO NOT EDIT.
require 'tmpdir'
require 'fileutils'
require 'net/http'
require 'uri'
require 'json'
require 'thread'
require 'time'


# create http-client to the server
begin
  @url = URI('<%= remoteAddress %>')
  @http = Net::HTTP.new(@url.host, @url.port);
rescue => e
  STDERR.puts("no connection to avian-service : #{e}")
  exit(false)
end

# send_request updates specified stage with the specified method
def send_request(method, id)
  begin
	uri = "%sRunnerService.%s" % [@url, method]
	request = Net::HTTP::Post.new(uri)
	request.body = {runner: '<%= runner.Name %>', stageID: id}.to_json
	request["Content-Type"] = "application/json"

    # Send the request
	@http.request(request)
	
  rescue => e
    # Handle the exception
    STDERR.puts("failed to to update stage id #{id} to: #{method} case: #{e}")
  end 
end

# Set stage to finish
def finish(id)
  send_request("FinishStage", id)
end

# Set stage to running
def start(id)
  send_request("StartStage", id)
end

# Set stage to failed
def failed(id)
  send_request("FailedStage", id)
end

@case_factory = $utilities.getCaseFactory

def open_case(settings)
  begin
    puts("Opening case in directory: #{settings['directory']}")
    caze = @case_factory.open(settings["directory"])
  
  rescue java.io.IOException
    begin
      puts("Creating case in directory: #{settings['directory']}")
      caze = @case_factory.create(settings['directory'], settings)

    rescue java.io.IOException => exception
	    STDERR.puts("problem creating new case, case might already be open: #{exception.backtrace}")
      exit(false)
    end
  end
  return caze
end

# tear down the cases 
def tear_down(single_case, compound_case, review_compound)
  begin
    puts('Starting case tear-down')
    unless compound_case.nil?
      puts('Adding single-case to compound')
      compound_case.add_child_case(single_case) # Add the newly processed case to the compound-case
      puts('Added single-case to compound-case')
      puts('Closing compound-case')
      compound_case.close()
      puts('Closed compound-case')
    else
      puts('Did not close compound-case')
    end

    unless review_compound.nil?
      puts('Adding single-case to review_compound')
      review_compound.add_child_case(single_case)
      puts('Added single-case to review_compound-case')
      puts('Closing review-compound')
      compound_case.close()
      puts('Closed review-compound')
    else
      puts('Did not close review-compound')
    end
    
    puts('Closing single-case')
    single_case.close()
    puts('Closed single-case')
  rescue => e
    # Handle the exception
    STDERR.puts("Failed to tear-down cases: #{e}")
    exit(false)
  end
end

begin
  # Create or open the single-case
  puts('Opening single-case: <%= runner.CaseSettings.Case.Name %>')
  single_case = open_case({ 
    'name' => '<%= runner.CaseSettings.Case.Name %>',
    'directory' => '<%= runner.CaseSettings.Case.Directory %>',
    'description' => '<%= runner.CaseSettings.Case.Description %>',
    'investigator' => '<%= runner.CaseSettings.Case.Investigator %>',
    'compound' => false,
  })
rescue => e
  # Handle the exception
  STDERR.puts("failed to create/open case: #{e}")
  exit(false)
end

<%= if (process(runner)) { %>
begin
  # Create or open the compound-case
  puts('Opening compound-case: <%= runner.CaseSettings.CompoundCase.Name %>')
  compound_case = open_case({ 
    'name' => '<%= runner.CaseSettings.CompoundCase.Name %>',
    'directory' => '<%= runner.CaseSettings.CompoundCase.Directory %>',
    'description' => '<%= runner.CaseSettings.CompoundCase.Description %>',
    'investigator' => '<%= runner.CaseSettings.CompoundCase.Investigator %>',
    'compound' => true,
  })

  # Create or open the review-compound
  puts('Opening review-compound: <%= runner.CaseSettings.ReviewCompound.Name %>')
  review_compound = open_case({ 
    'name' => '<%= runner.CaseSettings.ReviewCompound.Name %>',
    'directory' => '<%= runner.CaseSettings.ReviewCompound.Directory %>',
    'description' => '<%= runner.CaseSettings.ReviewCompound.Description %>',
    'investigator' => '<%= runner.CaseSettings.ReviewCompound.Investigator %>',
    'compound' => true,
  })
rescue => e
  # Handle the exception
  STDERR.puts("failed to create/open case: #{e}")
  exit(false)
end

begin
  # Check if the profile exists in the profile-store
  unless $utilities.get_processing_profile_store.contains_profile('<%= getProcessingProfile(runner) %>')
    # Import the profile
    puts("Did not find the requested processing-profile for reload in the profile-store")
    puts("Importing new processing-profile from <%= getProcessingProfilePath(runner) %>")
    $utilities.get_processing_profile_store.import_profile('<%= getProcessingProfilePath(runner) %>', '<%= getProcessingProfile(runner) %>')
    puts("Processing-profile has been imported")
  end

  # Create a processor to process the evidence for the case
  case_processor = single_case.create_processor
  case_processor.set_processing_profile('<%= getProcessingProfile(runner) %>')
  <%= for (i, evidence) in getEvidence(runner) { %>
  # Create container for evidence: <%= evidence.Name %>
  container_<%= i %> = case_processor.new_evidence_container('<%= evidence.Name %>')
  container_<%= i %>.add_file('<%= evidence.Directory %>')
  container_<%= i %>.set_description('<%= evidence.Description %>')
  container_<%= i %>.set_encoding('<%= evidence.Encoding %>')
  container_<%= i %>.set_time_zone('<%= evidence.TimeZone %>')
  container_<%= i %>.set_initial_custodian('<%= evidence.Custodian %>')
  container_<%= i %>.set_locale('<%= evidence.Locale %>')
  container_<%= i %>.save
  <% } %>
rescue => e
  # handle exception
  STDERR.puts("error initializing processor #{e}")
  tear_down(single_case, compound_case, review_compound)
  exit(false)
end

# Handle the items being processed
processed_item_count = 0
case_processor.when_item_processed do |processed_item|
  processed_item_count += 1
  puts("Item processed: #{processed_item.get_mime_type()} Count: #{processed_item_count}")
end

# Start the processing
begin
  # Start the process-stage (update api)
  start(<%= getProcessingStageID(runner) %>)

  case_processor.process

  # Finish the process-stage (update api)
  finish(<%= getProcessingStageID(runner) %>)
rescue => e
  # Handle the exception
  # Set the process-stage to failed (update api)
  tear_down(single_case, compound_case, review_compound)
  failed(<%= getProcessingStageID(runner) %>)
  STDERR.puts("Processing failed: #{e}")
  exit(false)
end
<% } else { %>
# Open single_case
puts('Opening single-case: <%= runner.CaseSettings.Case.Name %>')
single_case = open_case({ 
  'name' => '<%= runner.CaseSettings.Case.Name %>',
  'directory' => '<%= runner.CaseSettings.Case.Directory %>',
  'description' => '<%= runner.CaseSettings.Case.Description %>',
  'investigator' => '<%= runner.CaseSettings.Case.Investigator %>',
  'compound' => false,
})
<% } %><%= for (i, s) in getStages(runner) { %><%= if (searchAndTag(s)) { %>
# Start stage: <%= i %>
begin
  # Start SearchAndTag-stage (update api)
  start(<%= s.ID %>)

  puts('Starting Search And Tag-stage')<%= if (len(s.SearchAndTag.Files) != 0) { %>
  # Search And Tag with files
  puts('Creating bulk-searcher')
  bulk_searcher = single_case.create_bulk_searcher
  <%= for (file) in s.SearchAndTag.Files { %>
  puts('Adding file: <%= file.Path %> to bulk-searcher')
  bulk_searcher.import_file('<%= file.Path %>')
  <% } %>
  num_rows = bulk_searcher.row_count
  row_num = 0
  # Perform search and handle info
  puts('Starting search')
  bulk_searcher.run do |progress_info|
    puts("Searching through row #{row_num += 1}/#{num_rows}")
  end
<% } else { %>
  # Search And Tag with search-query
  items = single_case.search('<%= s.SearchAndTag.Search %>')
  puts("Found #{items.length} from search <%= s.SearchAndTag.Search %>")
  for item in items
      item.add_tag('<%= s.SearchAndTag.Tag %>')
  end
<% } %>
  # Finish the SearchAndTag-stage (update api)
  finish(<%= s.ID %>)
rescue => e
  # Handle the exception for stage
  
  # Set the SearchAndTag-stage to failed (update api)
  failed(<%= s.ID %>)
  <%= if (process(runner)) { %>
  # Tear down the cases
  tear_down(single_case, compound_case, review_compound)
  <% } else { %>
  # Tear down the single-case
  tear_down(single_case, nil, nil)
  <% } %>
  STDERR.puts("Failed to run stage id <%= s.ID %> : #{e}")
  exit(false)
end
<% } else if (exclude(s)) { %>
# Start stage: <%= i %>
begin
  # Start Exclude-stage (update api)
  start(<%= s.ID %>)

  # Exclude with reason
  puts('Starting Exclude-stage')
  items = single_case.search('<%= s.Exclude.Search %>')
  puts("Found #{items.length} from search <%= s.Exclude.Search %>")
  for item in items
    item.exclude('<%= s.Exclude.Reason %>')
    puts("Excluded item: #{item}")
  end
  # Finish the Exclude-stage (update api)
  finish(<%= s.ID %>)
rescue => e
  # Handle the exception for stage

  # Set the Exclude-stage to failed (update api)
  failed(<%= s.ID %>)
  <%= if (process(runner)) { %>
  # Tear down the cases
  tear_down(single_case, compound_case, review_compound)
  <% } else { %>
  # Tear down the single-case
  tear_down(single_case, nil, nil)
  <% } %>
  STDERR.puts("Failed to run stage id <%= s.ID %> : #{e}")
  exit(false)
end
<% } else if (ocr(s)) { %>
# Start stage: <%= i %>
begin
  # Start OCR-stage (update api)
  start(<%= s.ID %>)

  # Ocr
  puts('Starting OCR-stage')
  puts('Creating OCR-processor')
  ocr_processor = $utilities.createOcrProcessor

  # Check if the profile exists in the store
  unless $utilities.get_ocr_profile_store.contains_profile('<%= s.Ocr.Profile %>')
    # Import the profile
    puta('Did not find the requested ocr-profile in the profile-store')
    puts('Importing new ocr-profile from path <%= s.Ocr.ProfilePath %>')
    $utilities.get_ocr_profile_store.import_profile('<%= s.Ocr.ProfilePath %>', '<%= s.Ocr.Profile %>')
    puts("OCR-profile has been imported")
  end

  ocr_processor.set_ocr_profile('<%= s.Ocr.Profile %>')
  items = single_case.search('<%= s.Ocr.Search %>')
  puts("Found #{items.length} from search: <%= s.Ocr.Search %>")
  if items.length == 0 
    puts('No OCR items to process - skipping stage')
  else
    # variables to use for handling the ocr
    batch_index = 0
    target_batch_size = 1000
    last_progress = Time.now
    total_batches = (items.size.to_f / target_batch_size.to_f).ceil

    # Log the info for the stages
    ocr_processor.whenItemEventOccurs do |info|
      if (Time.now - last_progress) > 0.5
        last_progress = Time.now
        puts("OCR Stage: #{info.getStage} - Count: #{info.getStageCount} - Item: #{info.item.type.name} - GUID: #{info.item.guid}")
			end
    end

    items.each_slice(target_batch_size) do |slice_items|
      puts("Processing Batch #{batch_index+1}")
      ocr_job = ocr_processor.processAsync(slice_items)
      while !ocr_job.hasFinished
        puts("OCR Batch #{batch_index+1} - items: #{ocr_job.getCurrentStageExportedItemsCount}/#{slice_items.size}")
        sleep(0.25)
      end
      batch_index += 1
    end
  end

  # Finish the OCR-stage (update api)
  finish(<%= s.ID %>)
rescue => e
  # Handle the exception for stage

  # Set the OCR-stage to failed (update api)
  failed(<%= s.ID %>)
  <%= if (process(runner)) { %>
  # Tear down the cases
  tear_down(single_case, compound_case, review_compound)
  <% } else { %>
  # Tear down the single-case
  tear_down(single_case, nil, nil)
  <% } %>
  STDERR.puts("Failed to run stage id <%= s.ID %> : #{e}")
  exit(false)
end
<% } else if (populate(s)) { %>
# Start stage: <%= i %>
begin
  # Start Populate-stage (update api)
  start(<%= s.ID %>)

  # Populate stage
  tmpdir = Dir.tmpdir
  dir = "#{tmpdir}/populate"
  unless Dir.exist?(dir)
    puts("Creating tmp-dir: #{dir} for export")
    FileUtils.mkdir_p(dir)
  end

  puts('Creating batch-exporter with tmp-dir for populate')
  exporter = $utilities.create_batch_exporter(dir)
  <%= for (t) in s.Populate.Types { %>
  <%= if (t.Type == "native") { %>
  puts('Adding Native-product to exporter')
  exporter.addProduct("native",{
    "naming" => "guid",
    "path" => "Natives",
    "regenerateStored" => true,
  })
  <% } %><%= if (t.Type == "pdf") { %>
  puts('Adding PDF-product to exporter')
  exporter.addProduct("pdf",{
    "naming" => "guid",
    "path" => "PDFs",
    "regenerateStored" => true,
  })
  <% } %><% } %>
  items = single_case.search('<%= s.Populate.Search %>')
  puts("Found #{items.length} items from search: <%= s.Populate.Search %>")

  # Used to synchronize thread access in batch exported callback
  semaphore = Mutex.new

  # Setup batch exporter callback
  exporter.whenItemEventOccurs do |info|
    potential_failure = info.getFailure
    if !potential_failure.nil?
      event_item = info.getItem
      puts("Export failure for item: #{event_item.getGuid} : #{event_item.getLocalisedName}")
    end
    # Make the progress reporting have some thread safety
    semaphore.synchronize {
      puts("Exporting item: #{info.get_stage}")
    }
  end

  puts('Starting export of items')
  exporter.export_items(items)
  puts('Finished export of items')

  puts('Removing tmp-dir')
  FileUtils.rm_rf(dir)

  # Finish the Populate-stage (update api)
  finish(<%= s.ID %>)
rescue => e
  # Handle the exception for stage

  # Set the Populate-stage to failed (update api)
  failed(<%= s.ID %>)
  <%= if (process(runner)) { %>
  # Tear down the cases
  tear_down(single_case, compound_case, review_compound)
  <% } else { %>
  # Tear down the single-case
  tear_down(single_case, nil, nil)
  <% } %>
  STDERR.puts("Failed to run stage id <%= s.ID %> : #{e}")
  exit(false)
end
<% } else if (reload(s)) { %>
# Start stage: <%= i %>
begin
  # Start Reload-stage (update api)
  start(<%= s.ID %>)

  # Reload stage
  puts("Starting Reload-stage")

  # Check if the profile exists in the profile-store
  unless $utilities.get_processing_profile_store.contains_profile('<%= s.Reload.Profile %>')
    # Import the profile
    puts("Did not find the requested processing-profile for reload in the profile-store")
    puts("Importing new processing-profile from <%= s.Reload.ProfilePath %>")
    $utilities.get_processing_profile_store.import_profile('<%= s.Reload.ProfilePath %>', '<%= s.Reload.Profile %>')
    puts("Processing-profile has been imported")
  end

  items = single_case.search('<%= s.Reload.Search %>')
  puts("Found #{items.length} items from search: <%= s.Reload.Search %>")
  
  puts("Creating reload_processor")
  reload_processor = single_case.create_processor
  reload_processor.set_processing_profile('<%= s.Reload.Profile %>')
  reload_processor.reload_items_from_source_data(items)
  
  # Handle item-information from reload-processor
  reload_processor.when_item_processed do |processed_item|
    processed_item_count += 1
    puts("Item reloaded: #{processed_item.get_mime_type()} Count: #{processed_item_count}")
  end
  
  # Start the processing
  if items.length > 0
    puts('Starting the reload-process')
    reload_processor.process
    puts('Finished the reload-process')
  else
    puts('no items to process for reload')
  end

  # Finish the Reload-stage (update api)
  finish(<%= s.ID %>)
rescue => e
  # Handle the exception for stage

  # Set the Reload-stage to failed (update api)
  failed(<%= s.ID %>)
  <%= if (process(runner)) { %>
  # Tear down the cases
  tear_down(single_case, compound_case, review_compound)
  <% } else { %>
  # Tear down the single-case
  tear_down(single_case, nil, nil)
  <% } %>
  STDERR.puts("Failed to run stage id <%= s.ID %> : #{e}")
  exit(false)
end<% } %><% } %><% } %><% } %>
`
