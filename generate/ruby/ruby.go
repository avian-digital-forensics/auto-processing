package ruby

import (
	"html/template"

	api "github.com/avian-digital-forensics/auto-processing/pkg/avian-api"
	"github.com/avian-digital-forensics/auto-processing/pkg/avian-client"
	"github.com/avian-digital-forensics/auto-processing/pkg/inapp"
	"github.com/gobuffalo/plush"
)

// Generates a ruby script to be used by runner.
func Generate(remoteAddress, scriptDir string, runner api.Runner) (string, error) {
	ctx := plush.NewContext()

	// The code below defines functions that can be called when generating the ruby script.

	// Whether the the runner has an unfinished processing stage.
	ctx.Set("hasProcessingStage", func(runner api.Runner) bool {
		for _, stage := range runner.Stages {
			if stage.Process != nil && !avian.Finished(stage.Process.Status) {
				return true
			}
		}
		return false
	})

	// Whether the the runner has an unfinished in-app script stage.
	ctx.Set("hasInAppStage", func(runner api.Runner) bool {
		for _, stage := range runner.Stages {
			if stage.InApp != nil && !avian.Finished(stage.InApp.Status) {
				return true
			}
		}
		return false
	})

	// Gets the processing profile of the first processing stage.
	ctx.Set("getProcessingProfile", func(runner api.Runner) string {
		for _, stage := range runner.Stages {
			if stage.Process != nil {
				return stage.Process.Profile
			}
		}
		return ""
	})

	// Gets the settings file of the given in-app script settings as a string.
	ctx.Set("settingsFile", func(settings inapp.Settings) string {

		return settings.SettingsFile
	})

	// Gets the stage ID of the first processing stage.
	ctx.Set("getProcessingStageID", func(runner api.Runner) uint {
		for _, stage := range runner.Stages {
			if stage.Process != nil {
				return stage.ID
			}
		}
		return 0
	})

	// Returns whether the first processing stage has failed.
	ctx.Set("getProcessingFailed", func(runner api.Runner) bool {
		for _, stage := range runner.Stages {
			if stage.Process != nil {
				return (stage.Process.Status == avian.StatusFailed)
			}
		}
		return false
	})

	// Gets the path to the processing profile of the first processing stage.
	// Retuns "" if there is no processing stage.
	ctx.Set("getProcessingProfilePath", func(runner api.Runner) string {
		for _, stage := range runner.Stages {
			if stage.Process != nil {
				return stage.Process.ProfilePath
			}
		}
		return ""
	})

	// Gets the evidence store of the first processing stage.
	// Returns nil if there is no processing stage.
	ctx.Set("getEvidence", func(runner api.Runner) []*api.Evidence {
		for _, stage := range runner.Stages {
			if stage.Process != nil {
				return stage.Process.EvidenceStore
			}
		}
		return nil
	})

	// Returns all stages for the runner.
	ctx.Set("getStages", func(runner api.Runner) []*api.Stage { return runner.Stages })
	ctx.Set("elasticSearch", func(runner api.Runner) bool { return runner.CaseSettings.Case.ElasticSearch != nil })
	ctx.Set("isNoProcessing", func(stage *api.Stage) bool { return stage.Process == nil })
	// The next functions return for a stage whether they are the specic type and are unfinished.
	ctx.Set("searchAndTag", func(stage *api.Stage) bool {
		return stage.SearchAndTag != nil && !avian.Finished(stage.SearchAndTag.Status)
	})
	ctx.Set("exclude", func(stage *api.Stage) bool { return stage.Exclude != nil && !avian.Finished(stage.Exclude.Status) })
	ctx.Set("ocr", func(stage *api.Stage) bool { return stage.Ocr != nil && !avian.Finished(stage.Ocr.Status) })
	ctx.Set("populate", func(stage *api.Stage) bool { return stage.Populate != nil && !avian.Finished(stage.Populate.Status) })
	ctx.Set("reload", func(stage *api.Stage) bool { return stage.Reload != nil && !avian.Finished(stage.Reload.Status) })
	ctx.Set("inApp", func(stage *api.Stage) bool { return stage.InApp != nil && !avian.Finished(stage.InApp.Status) })
	ctx.Set("scanNewChildItems", func(stage *api.Stage) bool {
		return stage.ScanNewChildItems != nil && !avian.Finished(stage.ScanNewChildItems.Status)
	})
	ctx.Set("syncDescendants", func(stage *api.Stage) bool {
		return stage.SyncDescendants != nil && !avian.Finished(stage.SyncDescendants.Status)
	})

	ctx.Set("stageName", func(stage *api.Stage) string { return avian.Name(stage) })
	ctx.Set("formatQuotes", func(s string) template.HTML { return template.HTML(s) })
	ctx.Set("shouldRun", func(stage *api.Stage) bool { return avian.StageState(stage) != avian.StatusFinished })

	// Returns the remote address.
	ctx.Set("remoteAddress", remoteAddress)
	// Returns the path to the avian scripts directory.
	ctx.Set("scriptDir", scriptDir)
	// Returns the runner.
	ctx.Set("runner", runner)

	// Creates the template.
	return plush.Render(rubyTemplate, ctx)
}
