package ruby

import (
	"html/template"

	api "github.com/avian-digital-forensics/auto-processing/pkg/avian-api"
	"github.com/avian-digital-forensics/auto-processing/pkg/avian-client"
	"github.com/gobuffalo/plush"
)

func Generate(remoteAddress string, runner api.Runner) (string, error) {
	ctx := plush.NewContext()

	ctx.Set("process", func(r api.Runner) bool {
		for _, s := range r.Stages {
			if s.Process != nil && !avian.Finished(s.Process.Status) {
				return true
			}
		}
		return false
	})

	ctx.Set("getProcessingProfile", func(r api.Runner) string {
		for _, s := range r.Stages {
			if s.Process != nil {
				return s.Process.Profile
			}
		}
		return ""
	})

	ctx.Set("getProcessingStageID", func(r api.Runner) uint {
		for _, s := range r.Stages {
			if s.Process != nil {
				return s.ID
			}
		}
		return 0
	})

	ctx.Set("getProcessingFailed", func(r api.Runner) bool {
		for _, s := range r.Stages {
			if s.Process != nil {
				return (s.Process.Status == avian.StatusFailed)
			}
		}
		return false
	})

	ctx.Set("getProcessingProfilePath", func(r api.Runner) string {
		for _, s := range r.Stages {
			if s.Process != nil {
				return s.Process.ProfilePath
			}
		}
		return ""
	})

	ctx.Set("getEvidence", func(r api.Runner) []*api.Evidence {
		for _, s := range r.Stages {
			if s.Process != nil {
				return s.Process.EvidenceStore
			}
		}
		return nil
	})

	ctx.Set("getStages", func(r api.Runner) []*api.Stage { return r.Stages })
	ctx.Set("isProcess", func(s *api.Stage) bool { return s.Process != nil && !avian.Finished(s.Process.Status) })
	ctx.Set("searchAndTag", func(s *api.Stage) bool { return s.SearchAndTag != nil && !avian.Finished(s.SearchAndTag.Status) })
	ctx.Set("exclude", func(s *api.Stage) bool { return s.Exclude != nil && !avian.Finished(s.Exclude.Status) })
	ctx.Set("ocr", func(s *api.Stage) bool { return s.Ocr != nil && !avian.Finished(s.Ocr.Status) })
	ctx.Set("populate", func(s *api.Stage) bool { return s.Populate != nil && !avian.Finished(s.Populate.Status) })
	ctx.Set("reload", func(s *api.Stage) bool { return s.Reload != nil && !avian.Finished(s.Reload.Status) })
	ctx.Set("inApp", func(s *api.Stage) bool { return s.InApp != nil && !avian.Finished(s.InApp.Status) })
	ctx.Set("stageName", func(s *api.Stage) string { return avian.Name(s) })
	ctx.Set("formatQuotes", func(s string) template.HTML { return template.HTML(s) })

	ctx.Set("remoteAddress", remoteAddress)
	ctx.Set("runner", runner)
	return plush.Render(rubyTemplate, ctx)
}
