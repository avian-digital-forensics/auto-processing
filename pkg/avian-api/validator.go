package api

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/avian-digital-forensics/auto-processing/pkg/inapp"
	"github.com/pkg/errors"
)

const (
	workerTempDirLength int = 45
)

func (runner *Runner) Validate() error {
	if emptyString(runner.Name) {
		return errors.New("must specify unique name for runner")
	}

	if emptyString(runner.Hostname) {
		return errors.New("must specify 'hostname' for server to run the runner")
	}

	if emptyString(runner.Nms) {
		return errors.New("must specify 'nms' for licencesource")
	}

	if emptyString(runner.Licence) {
		return errors.New("must specify 'licence' for the correct licence-type")
	}

	if emptyString(runner.Xmx) {
		return errors.New("must specify 'xmx' for memory allocation in jvm")
	}

	// Validate Xmx.
	matchRegex, err := regexp.MatchString("^[0-9]+[kKmMgG]$", runner.Xmx)
	if err != nil {
		panic("Invalid regex in code.")
	}
	if !matchRegex {
		return fmt.Errorf("Invalid value for Xmx: %s. Must be a positive integer followed by k,K,m,M,g, or G.", runner.Xmx)
	}

	if runner.Workers == 0 {
		return errors.New("must specify amount of workers")
	}
	if runner.Workers <= 0 {
		return errors.New("Number of runners must be greater than zero.")
	}

	if err := runner.CaseSettings.Validate(); err != nil {
		return err
	}

	hasProcessingStage := false

	for i, stage := range runner.Stages {
		if err := stage.Validate(); err != nil {
			return err
		}
		if stage.Nil() {
			return fmt.Errorf("Stage: %d - unable to parse what stage it is - check syntax", i+1)
		}
		// Ensure that the runner only has a single processing stage.
		if stage.Process != nil {
			if hasProcessingStage {
				return fmt.Errorf("A runner may only have a single processing stage.")
			} else {
				hasProcessingStage = true
			}
		}

		// Check if Ocr or Populate is provided - case directory or spoolDir needs to be
		// less than 45 characters or else the processing will fail
		if stage.Ocr != nil || stage.Populate != nil {
			// Check if the case-directory has more than 45 characters
			if len(runner.CaseSettings.Case.Directory) > workerTempDirLength {
				spoolDirOK := false
				// iterate through the switches to see
				// if the spoolDir is provided
				spoolDirSwitch := "-Dnuix.export.spoolDir="
				for _, s := range runner.Switches {
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
		s.InApp == nil &&
		s.SyncDescendants == nil &&
		s.ScanNewChildItems == nil)
}

// Validate validates a Stage
func (s *Stage) Validate() error {
	if s.Process != nil {
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
			if !emptyString(evidence.Locale) {
				// Validate locale somewhat according to https://tools.ietf.org/html/rfc5646#section-2.1.1.
				matchRegex, err := regexp.MatchString("^(?:[a-zA-Z0-9]{1,8}-)[a-zA-Z0-9]{1,8}$", evidence.Locale)
				if err != nil {
					panic("Invalid regex in code.")
				}
				if !matchRegex {
					return fmt.Errorf("Invalid value for locale: %s. Must be alphanumeric with segments of maximum 8 length seperated by hyphens.", evidence.Locale)
				}
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
		if s.Ocr.BatchSize == 0 {
			return errors.New("must specify a batchSize for OCR-stage")
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

		var settings inapp.Settings
		if err := inapp.Config(s.InApp.Config, &settings); err != nil {
			return fmt.Errorf("failed to decode config for in-app script: %s - %v", s.InApp.Name, err)
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

	pathSwitches := []string{
		"-Dnuix.logdir=",
		"-java.io.tmpdir=",
		"-Dnuix.worker.tmpdir=",
		"-javaagent:",
		"-Dnuix.processing.sharedTempDirectory=",
		"-Dnuix.worker.jvm.arguments=-javaagent:",
	}

	if r.Switches != nil {
		for _, cmdSwitch := range r.Switches {
			for _, path := range pathSwitches {
				if strings.HasPrefix(cmdSwitch.Value, path) {
					paths = append(paths, strings.TrimPrefix(cmdSwitch.Value, path))
				}
			}
		}
	}
	return paths
}

func (r *Runner) HasInApp() bool {
	for _, s := range r.Stages {
		if s.InApp != nil {
			return true
		}
	}
	return false
}

func emptyString(s string) bool {
	return (len(s) == 0)
}
