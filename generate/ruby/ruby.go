package ruby

import (
	"html/template"

	api "github.com/avian-digital-forensics/auto-processing/pkg/avian-api"
	"github.com/avian-digital-forensics/auto-processing/pkg/avian-client"
	"github.com/avian-digital-forensics/auto-processing/pkg/inapp"
	"github.com/gobuffalo/plush"
)

// generates a ruby script to be used by runner
func Generate(remoteAddress, scriptDir string, runner api.Runner) (string, error) {
	ctx := plush.NewContext()

	// sets the processing settings
	ctx.Set("process", func(r api.Runner) bool {
		for _, s := range r.Stages {
			if s.Process != nil && !avian.Finished(s.Process.Status) {
				return true
			}
		}
		return false
	})

	// Sets the inapp script settings
	ctx.Set("hasInApp", func(r api.Runner) bool {
		for _, s := range r.Stages {
			if s.InApp != nil && !avian.Finished(s.InApp.Status) {
				return true
			}
		}
		return false
	})

	// Sets the processing profile
	ctx.Set("getProcessingProfile", func(r api.Runner) string {
		for _, s := range r.Stages {
			if s.Process != nil {
				return s.Process.Profile
			}
		}
		return ""
	})

	// "?
	ctx.Set("decodeSettings", func(s inapp.Settings) string {

		return s.SettingsFile
	})

	// sets the settings for finding processing stage ID's
	ctx.Set("getProcessingStageID", func(r api.Runner) uint {
		for _, s := range r.Stages {
			if s.Process != nil {
				return s.ID
			}
		}
		return 0
	})

	// sees if processing has failed
	ctx.Set("getProcessingFailed", func(r api.Runner) bool {
		for _, s := range r.Stages {
			if s.Process != nil {
				return (s.Process.Status == avian.StatusFailed)
			}
		}
		return false
	})

	// sets the processing profile path
	ctx.Set("getProcessingProfilePath", func(r api.Runner) string {
		for _, s := range r.Stages {
			if s.Process != nil {
				return s.Process.ProfilePath
			}
		}
		return ""
	})

	//sets the evidence paths
	ctx.Set("getEvidence", func(r api.Runner) []*api.Evidence {
		for _, s := range r.Stages {
			if s.Process != nil {
				return s.Process.EvidenceStore
			}
		}
		return nil
	})

	//sets the different stages
	ctx.Set("getStages", func(r api.Runner) []*api.Stage { return r.Stages })
	ctx.Set("elasticSearch", func(r api.Runner) bool { return r.CaseSettings.Case.ElasticSearch != nil })
	ctx.Set("isNoProcessing", func(s *api.Stage) bool { return s.Process == nil })
	ctx.Set("searchAndTag", func(s *api.Stage) bool { return s.SearchAndTag != nil && !avian.Finished(s.SearchAndTag.Status) })
	ctx.Set("exclude", func(s *api.Stage) bool { return s.Exclude != nil && !avian.Finished(s.Exclude.Status) })
	ctx.Set("ocr", func(s *api.Stage) bool { return s.Ocr != nil && !avian.Finished(s.Ocr.Status) })
	ctx.Set("populate", func(s *api.Stage) bool { return s.Populate != nil && !avian.Finished(s.Populate.Status) })
	ctx.Set("reload", func(s *api.Stage) bool { return s.Reload != nil && !avian.Finished(s.Reload.Status) })
	ctx.Set("inApp", func(s *api.Stage) bool { return s.InApp != nil && !avian.Finished(s.InApp.Status) })
	ctx.Set("scanNewChildItems", func(s *api.Stage) bool {
		return s.ScanNewChildItems != nil && !avian.Finished(s.ScanNewChildItems.Status)
	})
	ctx.Set("syncDescendants", func(s *api.Stage) bool { return s.SyncDescendants != nil && !avian.Finished(s.SyncDescendants.Status) })
	ctx.Set("stageName", func(s *api.Stage) string { return avian.Name(s) })
	ctx.Set("formatQuotes", func(s string) template.HTML { return template.HTML(s) })
	ctx.Set("shouldRun", func(s *api.Stage) bool { return avian.StageState(s) != avian.StatusFinished })

	//sets the remote adress and scripts directory
	ctx.Set("remoteAddress", remoteAddress)
	ctx.Set("scriptDir", scriptDir)
	ctx.Set("runner", runner)

	//creates the template
	return plush.Render(rubyTemplate, ctx)
}
