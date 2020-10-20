package api

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

const (
	workerTempDirLength int = 45
)

func (r *Runner) Validate() error {
	if emptyString(r.Name) {
		return errors.New("must specify unique name for runner")
	}

	if emptyString(r.Hostname) {
		return errors.New("must specify 'hostname' for server to run the runner")
	}

	if emptyString(r.Nms) {
		return errors.New("must specify 'nms' for licencesource")
	}

	if emptyString(r.Licence) {
		return errors.New("must specify 'licence' for the correct licence-type")
	}

	if emptyString(r.Xmx) {
		return errors.New("must specify 'xmx' for memory allocation in jvm")
	}

	if r.Workers == 0 {
		return errors.New("must specify amount of workers")
	}

	if err := r.CaseSettings.Validate(); err != nil {
		return err
	}

	for i, stage := range r.Stages {
		if err := stage.Validate(); err != nil {
			return err
		}
		if stage.Nil() {
			return fmt.Errorf("Stage: %d - unable to parse what stage it is - check syntax", i+1)
		}

		// Check if Ocr or Populate is provided - case directory or spoolDir needs to be
		// less than 45 characters or else the processing will fail
		if stage.Ocr != nil || stage.Populate != nil {
			// Check if the case-directory has more than 45 characters
			if len(r.CaseSettings.Case.Directory) > workerTempDirLength {
				spoolDirOK := false
				// iterate through the switches to see
				// if the spoolDir is provided
				spoolDirSwitch := "-Dnuix.export.spoolDir="
				for _, s := range r.Switches {
					if strings.HasPrefix(s.Value, spoolDirSwitch) {
						spoolDir := strings.TrimPrefix(s.Value, spoolDirSwitch)
						// set spoolDirOK to true if the spoolDir has less than 45 characters
						if len(spoolDir) < workerTempDirLength {
							spoolDirOK = true
						}
					}
				}

				// return error if the case-dir or spoolDir has more than 45 characters
				if !spoolDirOK {
					return fmt.Errorf("provide a path with less than %d characters in the switch: '%s' to perform ocr/populate", workerTempDirLength, spoolDirSwitch)
				}
			}
		}

		stage.Index = uint(i)
	}
	return nil
}

func (s *Stage) Nil() bool {
	return (s.Process == nil &&
		s.SearchAndTag == nil &&
		s.Exclude == nil &&
		s.Reload == nil &&
		s.Populate == nil &&
		s.Ocr == nil &&
		s.InApp == nil)
}

// Validate validates a Stage
func (s *Stage) Validate() error {
	if s.Process != nil {
		if emptyString(s.Process.Profile) {
			return errors.New("must specify processing-profile for process-stage")
		}

		if len(s.Process.EvidenceStore) == 0 {
			return errors.New("must specify evidence for the process-stage")
		}

		for i, evidence := range s.Process.EvidenceStore {
			if emptyString(evidence.Name) {
				return fmt.Errorf("must specify name for evidence: #%d", i)
			}
			if emptyString(evidence.Directory) {
				return fmt.Errorf("must specify directory for evidence: #%d", i)
			}
		}
	}

	if s.SearchAndTag != nil {
		if emptyString(s.SearchAndTag.Search) {
			if len(s.SearchAndTag.Files) == 0 {
				return errors.New("must specify a search-query or files for search and tag-stage")
			}
			for i, file := range s.SearchAndTag.Files {
				if emptyString(file.Path) {
					return fmt.Errorf("must specify path to file for search and tag #%d", i)
				}
			}
		} else {
			if emptyString(s.SearchAndTag.Tag) {
				return errors.New("must specify a tag for search and tag")
			}
		}
	}

	if s.Populate != nil {
		if emptyString(s.Populate.Search) {
			return errors.New("must specify a search-query for populate-stage")
		}

		if len(s.Populate.Types) == 0 {
			return errors.New("must specify types for populate-stage")
		}

		for i, t := range s.Populate.Types {
			if emptyString(t.Type) {
				return fmt.Errorf("must specify type for populate-stage type #%d", i)
			}
		}
	}

	if s.Ocr != nil {
		if emptyString(s.Ocr.Profile) {
			return errors.New("must specify a processing-profile for OCR-stage")
		}
		if emptyString(s.Ocr.Search) {
			return errors.New("must specify a search-query for OCR-stage")
		}
	}

	if s.Exclude != nil {
		if emptyString(s.Exclude.Search) {
			return errors.New("must specify a search-query for exclude-stage")
		}
		if emptyString(s.Exclude.Reason) {
			return errors.New("must specify a reason for exclude-stage")
		}
	}

	if s.InApp != nil {
		if emptyString(s.InApp.Name) {
			return errors.New("must specify a name for in-app script")
		}
		if emptyString(s.InApp.Config) {
			return errors.New("must specify a config for in-app script")
		}

	}
	return nil
}

// Validate validates CaseSettings
func (s *CaseSettings) Validate() error {
	if s == nil {
		return errors.New("must specify 'caseSettings' in runner-config")
	}
	if emptyString(s.CaseLocation) {
		return errors.New("must specify caseLocation for caseSettings")
	}
	return nil
}

// Paths returns all the specified-paths for the runner
func (r *Runner) Paths() []string {
	var paths []string
	if r.CaseSettings != nil {
		paths = append(paths, r.CaseSettings.CaseLocation)
	}

	for _, stage := range r.Stages {
		if stage.Process != nil {
			paths = append(paths, stage.Process.ProfilePath)
			for _, evidence := range stage.Process.EvidenceStore {
				paths = append(paths, evidence.Directory)
			}
		}

		if stage.SearchAndTag != nil {
			for _, file := range stage.SearchAndTag.Files {
				paths = append(paths, file.Path)
			}
		}

		if stage.Ocr != nil {
			paths = append(paths, stage.Ocr.ProfilePath)
		}

		if stage.Reload != nil {
			paths = append(paths, stage.Reload.ProfilePath)
		}

		if stage.InApp != nil {
			paths = append(paths, stage.InApp.Config)
		}
	}
	return paths
}

func emptyString(s string) bool {
	return (len(s) == 0)
}
