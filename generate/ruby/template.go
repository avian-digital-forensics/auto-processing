package ruby

var rubyTemplate = `# Code generated by Avian; DO NOT EDIT.
require 'tmpdir'
require 'fileutils'
require 'net/http'
require 'uri'
require 'json'
require 'thread'
require 'time'

STDOUT.puts('STARTING RUNNER')

def send_request(method, body)
  begin
    # create http-client to the server
    url = URI('<%= remoteAddress %>')
    http = Net::HTTP.new(url.host, url.port)
    uri = "%sRunnerService.%s" % [url, method]
    request = Net::HTTP::Post.new(uri)
    request.body = body.to_json
    request["Content-Type"] = "application/json"
    http.request(request)

  rescue => e
    # Handle the exception
    if method == 'Start'
      STDOUT.puts('FINISHED RUNNER')
      STDERR.puts("no connection to avian-service : #{e}")
      exit(false)
    end
    STDERR.puts("failed to send request to: #{method} case: #{e}")
  end
end

# Set runner to running
def start_runner
  send_request('Start', {runner: '<%= runner.Name %>', id: <%= runner.ID %>})
end

# Set runner to failed
def failed_runner(exception)
  send_request('Failed', {runner: '<%= runner.Name %>', id: <%= runner.ID %>, exception: exception})
end

# Set runner to finished
def finish_runner
  send_request('Finish', {runner: '<%= runner.Name %>', id: <%= runner.ID %>})
end

# Set stage to failed
def finish(id)
  send_request('FinishStage', {runner: '<%= runner.Name %>', stageID: id})
end

# Set stage to running
def start(id)
  send_request('StartStage', {runner: '<%= runner.Name %>', stageID: id})
end

# Set stage to failed
def failed(id)
  send_request('FailedStage', {runner: '<%= runner.Name %>', stageID: id})
end

def log_item(stage, stage_id, message, count, mime_type, guid, processStage)
  item = {
    runner: '<%= runner.Name %>', 
    stage: stage, 
    stageID: stage_id,
    message: message,
    count: count,
    mimeType: mime_type, 
    gUID: guid, 
    processStage: processStage,
  }
  send_request('LogItem', item)
end

def log_debug(stage, stage_id, message)
  send_request('LogDebug', {
    runner: '<%= runner.Name %>', 
    stage: stage, 
    stageID: stage_id,
    message: message,
  })
end

def log_info(stage, stage_id, message)
  send_request('LogInfo', {
    runner: '<%= runner.Name %>', 
    stage: stage, 
    stageID: stage_id,
    message: message,
  })
end

def log_error(stage, stage_id, message, exception)
  send_request('LogError', {
    runner: '<%= runner.Name %>', 
    stage: stage, 
    stageID: stage_id,
    message: message,
    exception: exception,
  })
end

Thread.new {
  loop do
    sleep 90
    send_request('Heartbeat', {runner: '<%= runner.Name %>', id: <%= runner.ID %>})
  end
}

# start the runner
start_runner

@case_factory = $utilities.getCaseFactory

def open_case(settings)
  begin
    unless java.io.File.new("#{settings['directory']}\\case.fbi2").exists
      log_info("", 0, "Creating case in directory: #{settings['directory']}")
      caze = @case_factory.create(settings['directory'], settings)
    else
      log_info("", 0, "Opening case in directory: #{settings['directory']}")
      caze = @case_factory.open(settings["directory"])
    end
  rescue => e
    log_error("", 0, "Cannot create/open case, case might already be open", e.backtrace)
    STDERR.puts("problem creating new case, case might already be open: #{e.backtrace}")
    failed_runner("problem creating new case, case might already be open: #{e.backtrace}")
    STDOUT.puts('FINISHED RUNNER')
    exit(false)
  end
  return caze
end

# tear down the cases 
def tear_down(single_case, compound_case, review_compound)
  begin
    log_debug('', 0, 'Starting case tear-down')
    unless compound_case.nil?
      if compound_case.is_compound
        unless compound_case.child_cases.include? single_case
          log_info('', 0, 'Adding single-case to compound')
          compound_case.add_child_case(single_case) # Add the newly processed case to the compound-case
          log_debug('', 0, 'Added single-case to compound-case')
        end
      end
     
      unless compound_case.is_closed
        log_info('', 0, 'Closing compound-case')
        compound_case.close
        log_debug('', 0, 'Closed compound-case')
      end
    else
    log_debug('', 0, 'No compound-case to tear down')
    end

    unless review_compound.nil?
      if review_compound.is_compound
        unless review_compound.child_cases.include? single_case
          log_info('', 0, 'Adding single-case to review-compound')
          review_compound.add_child_case(single_case) # Add the newly processed case to the compound-case
          log_debug('', 0, 'Added single-case to review-compound')
        end
      end
    
      unless compound_case.is_closed
        log_info('', 0, 'Closing compound-case')
        compound_case.close
        log_debug('', 0, 'Closed compound-case')
      end
    else
    log_debug('', 0, 'No review-compound to tear down')
    end
    
    unless single_case.is_closed
      log_info('', 0, 'Closing single-case')
      single_case.close
      log_debug('', 0, 'Closed single-case')
    else
      log_debug('', 0, 'Single-case already closed')
    end
    log_debug('', 0, 'Case tear-down finished')
  rescue => e
    # Handle the exception
    log_error('', 0, 'Failed to tear-down cases', e)
  end
end

# Create or open the single-case
log_info('', 0, 'Opening single-case: <%= runner.CaseSettings.Case.Name %>')
single_case = open_case({ 
  'name' => '<%= runner.CaseSettings.Case.Name %>',
  'directory' => '<%= runner.CaseSettings.Case.Directory %>',
  'description' => '<%= runner.CaseSettings.Case.Description %>',
  'investigator' => '<%= runner.CaseSettings.Case.Investigator %>',
  'compound' => false,
})
<%= if (process(runner)) { %><%= if (!getProcessingFailed(runner)) { %>
# Create or open the compound-case
log_info('', 0, 'Opening compound-case: <%= runner.CaseSettings.CompoundCase.Name %>')
compound_case = open_case({ 
  'name' => '<%= runner.CaseSettings.CompoundCase.Name %>',
  'directory' => '<%= runner.CaseSettings.CompoundCase.Directory %>',
  'description' => '<%= runner.CaseSettings.CompoundCase.Description %>',
  'investigator' => '<%= runner.CaseSettings.CompoundCase.Investigator %>',
  'compound' => true,
})

# Create or open the review-compound
log_info('', 0, 'Opening review-compound: <%= runner.CaseSettings.ReviewCompound.Name %>')
review_compound = open_case({ 
  'name' => '<%= runner.CaseSettings.ReviewCompound.Name %>',
  'directory' => '<%= runner.CaseSettings.ReviewCompound.Directory %>',
  'description' => '<%= runner.CaseSettings.ReviewCompound.Description %>',
  'investigator' => '<%= runner.CaseSettings.ReviewCompound.Investigator %>',
  'compound' => true,
})<% } %>

begin
  # Check if the profile exists in the profile-store
  unless $utilities.get_processing_profile_store.contains_profile('<%= getProcessingProfile(runner) %>')
    # Import the profile
    log_debug('', 0, 'Did not find the requested processing-profile in the profile-store')
    log_info('', 0, 'Importing new processing-profile from <%= getProcessingProfilePath(runner) %>')
    $utilities.get_processing_profile_store.import_profile('<%= getProcessingProfilePath(runner) %>', '<%= getProcessingProfile(runner) %>')
    log_debug('', 0, 'Processing-profile has been imported')
  end

  # Create a processor to process the evidence for the case
  log_info('', 0, 'Creating processor for case-processing')
  case_processor = single_case.create_processor
  case_processor.set_processing_profile('<%= getProcessingProfile(runner) %>')
  <%= if (getProcessingFailed(runner)) { %>case_processor.rescan_evidence_repositories(true)<% } else { %>
  <%= for (i, evidence) in getEvidence(runner) { %>
  # Create container for evidence: <%= evidence.Name %>
  log_info('', 0, 'Adding evidence-container to case')
  container_<%= i %> = case_processor.new_evidence_container('<%= evidence.Name %>')
  container_<%= i %>.add_file('<%= evidence.Directory %>')
  container_<%= i %>.set_description('<%= evidence.Description %>')
  container_<%= i %>.set_encoding('<%= evidence.Encoding %>')
  container_<%= i %>.set_time_zone('<%= evidence.TimeZone %>')
  container_<%= i %>.set_initial_custodian('<%= evidence.Custodian %>')
  container_<%= i %>.set_locale('<%= evidence.Locale %>')
  container_<%= i %>.save
  <% } %><% } %>
rescue => e
  # handle exception
  log_error('', 0, 'Cannot initialize processor', e)
  STDOUT.puts('FINISHED RUNNER')
  STDERR.puts("error initializing processor #{e}")
  tear_down(single_case, compound_case, review_compound)
  failed_runner(e)
  exit(false)
end

# Start the processing
begin
  # Start the process-stage (update api)
  start(<%= getProcessingStageID(runner) %>)

  # Handle the items being processed
  semaphore = Mutex.new
  processed_count = 0
  case_processor.when_item_processed do |info|
    semaphore.synchronize {
      processed_count += 1
      log_item('Process', <%= getProcessingStageID(runner) %>, 'Processed item', processed_count, info.mime_type, info.guid_path, '')
    }
  end

  log_info('Process', <%= getProcessingStageID(runner) %>, 'Start case-processing')
  case_processor.process
  log_info('Process', <%= getProcessingStageID(runner) %>, 'Finished case-processing')

  # Finish the process-stage (update api)
  finish(<%= getProcessingStageID(runner) %>)
rescue => e
  # Handle the exception
  # Set the process-stage to failed (update api)
  failed(<%= getProcessingStageID(runner) %>)
  tear_down(single_case, compound_case, review_compound)
  log_error('Process', <%= getProcessingStageID(runner) %>, 'Processing failed', e)
  STDOUT.puts('FINISHED RUNNER')
  STDERR.puts("Processing failed: #{e}")
  failed_runner(e)
  exit(false)
end
<% } %><%= for (i, s) in getStages(runner) { %><%= if (searchAndTag(s)) { %>
# Start stage: <%= i %>
begin
  # Start SearchAndTag-stage (update api)
  start(<%= s.ID %>)

  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Starting SearchAndTag-stage')<%= if (len(s.SearchAndTag.Files) != 0) { %>
  # Search And Tag with files
  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Creating bulk-searcher')
  bulk_searcher = single_case.create_bulk_searcher
  <%= for (file) in s.SearchAndTag.Files { %>
  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Adding file: <%= file.Path %> to bulk-searcher')
  bulk_searcher.import_file('<%= file.Path %>')
  <% } %>
  num_rows = bulk_searcher.row_count
  row_num = 0
  # Perform search and handle info
  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Starting search')
  bulk_searcher.run do |info|
    row_num += 1
    log_item('<%= stageName(s) %>', <%= s.ID %>, 'Searching through row - current size: #{info.current_size} - total size: #{info.total_size}', row_num, '', '', '')
  end
<% } else { %>
  # Search And Tag with search-query
  items = single_case.search('<%= formatQuotes(s.SearchAndTag.Search) %>')
  log_debug('<%= stageName(s) %>', <%= s.ID %>, "Found #{items.length} from search <%= s.SearchAndTag.Search %> - starts tagging")
  item_count = 0
  for item in items
    item.add_tag('<%= s.SearchAndTag.Tag %>')
    item_count += 1
    log_item('<%= stageName(s) %>', <%= s.ID %>, 'Tagged item', item_count, item.type.name, item.guid, '')
  end
<% } %>
  # Finish the SearchAndTag-stage (update api)
  log_debug('<%= stageName(s) %>', <%= s.ID %>, 'Finished')
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
  log_error('<%= stageName(s) %>', <%= s.ID %>, 'Failed', e)
  STDOUT.puts('FINISHED RUNNER')
  STDERR.puts("Failed to run stage <%= stageName(s) %> id <%= s.ID %> : #{e}")
  failed_runner(e)
  exit(false)
end
<% } else if (exclude(s)) { %>
# Start stage: <%= i %>
begin
  # Start Exclude-stage (update api)
  start(<%= s.ID %>)

  # Exclude with reason
  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Starting Exclude-stage')
  items = single_case.search('<%= formatQuotes(s.Exclude.Search) %>')
  log_debug('<%= stageName(s) %>', <%= s.ID %>, "Found #{items.length} from search <%= s.Exclude.Search %> - starts excluding")
  item_count = 0
  for item in items
    item.exclude('<%= s.Exclude.Reason %>')
    item_count += 1
    log_item('<%= stageName(s) %>', <%= s.ID %>, 'Excluded item', item_count, item.type.name, item.guid, '')
  end
  # Finish the Exclude-stage (update api)
  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Finished')
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
  log_error('<%= stageName(s) %>', <%= s.ID %>, 'Failed', e)
  STDOUT.puts('FINISHED RUNNER')
  STDERR.puts("Failed to run stage <%= stageName(s) %> id <%= s.ID %> : #{e}")
  failed_runner(e)
  exit(false)
end
<% } else if (ocr(s)) { %>
# Start stage: <%= i %>
begin
  # Start OCR-stage (update api)
  start(<%= s.ID %>)

  # Ocr
  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Starting OCR-stage')
  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Creating OCR-processor')
  ocr_processor = $utilities.createOcrProcessor

  # Check if the profile exists in the store
  unless $utilities.get_ocr_profile_store.contains_profile('<%= s.Ocr.Profile %>')
    # Import the profile
    log_debug('<%= stageName(s) %>', <%= s.ID %>, 'Did not find the requested ocr-profile in the profile-store')
    log_info('<%= stageName(s) %>', <%= s.ID %>, 'Importing new ocr-profile from path <%= s.Ocr.ProfilePath %>')
    $utilities.get_ocr_profile_store.import_profile('<%= s.Ocr.ProfilePath %>', '<%= s.Ocr.Profile %>')
    log_debug('<%= stageName(s) %>', <%= s.ID %>, 'OCR-profile has been imported')
  end

  ocr_profile = $utilities.get_ocr_profile_store.get_profile('<%= s.Ocr.Profile %>')
  ocr_items = single_case.search('<%= formatQuotes(s.Ocr.Search) %>')
  log_debug('<%= stageName(s) %>', <%= s.ID %>, "Found #{ocr_items.length} from search: <%= s.Ocr.Search %> - starts ocr")
  if ocr_items.length == 0 
    log_info('<%= stageName(s) %>', <%= s.ID %>, 'No OCR items to process - skipping stage')
  else
    # Log the info for the items
    ocr_sempahore = Mutex.new
    processed_approx_count = 0
    ocr_processor.when_item_event_occurs do |info|
      ocr_sempahore.synchronize {
        processed_approx_count += 1
        log_item('<%= stageName(s) %>', <%= s.ID %>, 'OCR item', info.stage_count, info.item.type.name, info.item.guid, info.stage)
      }
    end

    # variables to use for batched ocr
    batch_index = 0
    target_batch_size = 100
    total_batches = (ocr_items.size.to_f / target_batch_size.to_f).ceil

    ocr_items.each_slice(target_batch_size) do |slice_items|
      log_info('<%= stageName(s) %>', <%= s.ID %>, "Start ocr-processing batch : #{batch_index+1}/#{total_batches}")
      ocr_processor.process(slice_items, ocr_profile)
      batch_index += 1
    end
  end

  # Finish the OCR-stage (update api)
  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Finished')
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
  log_error('<%= stageName(s) %>', <%= s.ID %>, 'Failed', e)
  STDOUT.puts('FINISHED RUNNER')
  STDERR.puts("Failed to run stage <%= stageName(s) %> id <%= s.ID %> : #{e}")
  failed_runner(e)
  exit(false)
end
<% } else if (populate(s)) { %>
# Start stage: <%= i %>
begin
  # Start Populate-stage (update api)
  start(<%= s.ID %>)
  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Starting stage')

  # Populate stage
  tmpdir = Dir.tmpdir
  dir = "#{tmpdir}/populate"
  unless Dir.exist?(dir)
    log_info('<%= stageName(s) %>', <%= s.ID %>, "Creating tmp-dir: #{dir} for export")
    FileUtils.mkdir_p(dir)
  end

  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Creating batch-exporter with tmp-dir for populate')
  exporter = $utilities.create_batch_exporter(dir)
  <%= for (t) in s.Populate.Types { %>
  <%= if (t.Type == "native") { %>
  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Adding Native-product to exporter')
  exporter.addProduct("native",{
    "naming" => "guid",
    "path" => "Natives",
    "regenerateStored" => true,
  })
  <% } %><%= if (t.Type == "pdf") { %>
  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Adding PDF-product to exporter')
  exporter.addProduct("pdf",{
    "naming" => "guid",
    "path" => "PDFs",
    "regenerateStored" => true,
  })
  <% } %><% } %>
  items = single_case.search('<%= formatQuotes(s.Populate.Search) %>')
  log_debug('<%= stageName(s) %>', <%= s.ID %>, "Found #{items.length} items from search: <%= s.Populate.Search %> - starts export for populate")

  # Used to synchronize thread access in batch exported callback
  semaphore = Mutex.new

  # Setup batch exporter callback
  exporter.when_item_event_occurs do |info|
    if !info.failure.nil?
      log_error('<%= stageName(s) %>', <%= s.ID %>, "Export failure for item: #{info.item.guid} : #{info.item.localised_name}", '')
    end
    # Make the progress reporting have some thread safety
    semaphore.synchronize {
      log_item('Populate', <%= s.ID %>, 'Exporting item', info.stage_count, info.item.type.name, info.item.guid, info.stage)
    }
  end

  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Starting export of items')
  exporter.export_items(items)
  log_debug('<%= stageName(s) %>', <%= s.ID %>, 'Finished export of items')

  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Removing tmp-dir')
  FileUtils.rm_rf(dir)
  log_debug('<%= stageName(s) %>', <%= s.ID %>, 'Removed tmp-dir')

  # Finish the Populate-stage (update api)
  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Finished')
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
  log_error('<%= stageName(s) %>', <%= s.ID %>, 'Failed', e)
  STDOUT.puts('FINISHED RUNNER')
  STDERR.puts("Failed to run stage <%= stageName(s) %> id <%= s.ID %> : #{e}")
  failed_runner(e)
  exit(false)
end
<% } else if (reload(s)) { %>
# Start stage: <%= i %>
begin
  # Start Reload-stage (update api)
  start(<%= s.ID %>)

  # Reload stage
  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Starting Reload-stage')

  # Check if the profile exists in the profile-store
  unless $utilities.get_processing_profile_store.contains_profile('<%= s.Reload.Profile %>')
    # Import the profile
    log_debug('<%= stageName(s) %>', <%= s.ID %>, 'Did not find the requested processing-profile for reload in the profile-store')
    log_info('<%= stageName(s) %>', <%= s.ID %>, 'Importing new processing-profile from <%= s.Reload.ProfilePath %>')
    $utilities.get_processing_profile_store.import_profile('<%= s.Reload.ProfilePath %>', '<%= s.Reload.Profile %>')
    log_debug('<%= stageName(s) %>', <%= s.ID %>, 'Processing-profile has been imported')
  end

  items = single_case.search('<%= formatQuotes(s.Reload.Search) %>')
  log_debug('<%= stageName(s) %>', <%= s.ID %>, "Found #{items.length} items from search: <%= s.Reload.Search %>")
  
  log_info('<%= stageName(s) %>', <%= s.ID %>, 'Creating reload_processor')
  reload_processor = single_case.create_processor
  log_debug('<%= stageName(s) %>', <%= s.ID %>, 'Created reload_processor')
  reload_processor.set_processing_profile('<%= s.Reload.Profile %>')
  reload_processor.reload_items_from_source_data(items)
  
  # Handle item-information from reload-processor
  sempahore = Mutex.new
  reload_count = 0
  reload_processor.when_item_processed do |info|
    semaphore.synchronize {
      reload_count += 1
      log_item('Reload', <%= s.ID %>, 'Reloaded item', reload_count, info.mime_type, info.guid_path, '')
    }
  end
  
  # Start the processing
  if items.length > 0
    log_info('<%= stageName(s) %>', <%= s.ID %>, 'Starts the reload-processing')
    reload_processor.process
    log_debug('<%= stageName(s) %>', <%= s.ID %>, 'Finished the reload-processing')
  else
    log_debug('<%= stageName(s) %>', <%= s.ID %>, 'No items to process for reload')
  end

  # Finish the Reload-stage (update api)
  log_debug('<%= stageName(s) %>', <%= s.ID %>, 'Finished')
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
  log_error('<%= stageName(s) %>', <%= s.ID %>, 'Failed', e)
  STDOUT.puts('FINISHED RUNNER')
  STDERR.puts("Failed to run stage <%= stageName(s) %> id <%= s.ID %> : #{e}")
  failed_runner(e)
  exit(false)
end<% } %><% } %><% } %><% } %>
STDOUT.puts('FINISHED RUNNER')
finish_runner`
