package configs

import (
	"errors"
	"fmt"
	"os"
	"strings"

	avian "github.com/avian-digital-forensics/auto-processing/pkg/avian-client"

	"gopkg.in/yaml.v2"
)

// Defines the yaml config.
type Config struct {
	API API `yaml:"api"`
}

// Defines the api.
type API struct {
	Servers []Servers                `yaml:"servers"`
	Nms     avian.NmsApplyRequests   `yaml:"nmsApply"`
	Runner  avian.RunnerApplyRequest `yaml:"runner"`
}

// Defines the servers config.
type Servers struct {
	Server avian.ServerApplyRequest `yaml:"server"`
}

// Validates the runner config.
// Returns an error if any are found or nil if the config is valid.
func ValidateRunnerConfig(runner avian.RunnerApplyRequest) error {
	if runner.CaseSettings == nil {
		return errors.New("specify caseSettings and caseLocation")
	}

	if runner.CaseSettings.CaseLocation == "" {
		return errors.New("must specify caseLocation for caseSettings")
	}
	return nil
}

// Performs necessary post-processing for runner configs.
// For example sets case names based on runner name and therafter lowercases the runner name.
func PostprocessRunnerConfig(runner avian.RunnerApplyRequest) avian.RunnerApplyRequest {
	if runner.CaseSettings.Case == nil {
		runner.CaseSettings.Case = &avian.Case{}
	}

	if runner.CaseSettings.Case.Name == "" {
		runner.CaseSettings.Case.Name = runner.Name + "-single"
	}

	if runner.CaseSettings.Case.Directory == "" {
		runner.CaseSettings.Case.Directory = fmt.Sprintf("%s/%s-single",
			runner.CaseSettings.CaseLocation,
			runner.Name,
		)
	}

	// Checks if compound case has been set.
	if runner.CaseSettings.CompoundCase == nil || runner.CaseSettings.CompoundCase.Directory == "" {
		var compound_description string
		var compound_investigator string
		if runner.CaseSettings.CompoundCase != nil {
			compound_description = runner.CaseSettings.ReviewCompound.Description
			compound_investigator = runner.CaseSettings.ReviewCompound.Investigator
		}

		runner.CaseSettings.CompoundCase = &avian.Case{
			Name: runner.Name + "-compound",
			Directory: fmt.Sprintf("%s/%s-compound",
				runner.CaseSettings.CaseLocation,
				runner.Name,
			),
			Description:  compound_description,
			Investigator: compound_investigator,
		}
	}

	//checks if review case has been set
	if runner.CaseSettings.ReviewCompound == nil || runner.CaseSettings.ReviewCompound.Directory == "" {
		var review_description string
		var review_investigator string
		if runner.CaseSettings.ReviewCompound != nil {
			review_description = runner.CaseSettings.ReviewCompound.Description
			review_investigator = runner.CaseSettings.ReviewCompound.Investigator
		}

		runner.CaseSettings.ReviewCompound = &avian.Case{
			Name: runner.Name + "-review",
			Directory: fmt.Sprintf("%s/%s-review",
				runner.CaseSettings.CaseLocation,
				runner.Name,
			),
			Description:  review_description,
			Investigator: review_investigator,
		}
	}

	runner.Name = strings.ToLower(runner.Name)
	runner.Hostname = strings.ToLower(runner.Hostname)

	return runner
}

// Validates the server config.
// Returns an error if any are found or nil if the config is valid.
func ValidateServerConfig(server avian.ServerApplyRequest) error {
	return nil
}

// Performs necessary post-processing for server configs.
// For example sets the hostname to lower case.
func PostprocessServerConfig(server avian.ServerApplyRequest) avian.ServerApplyRequest {
	server.Hostname = strings.ToLower(server.Hostname)

	return server
}

// Decodes and reads the yaml.
func readYAML(path string, cfg *Config) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := yaml.NewDecoder(file)
	return decoder.Decode(cfg)
}

// Get returns data from yml file specified as path.
func Get(path string) (*Config, error) {
	var cfg Config
	err := readYAML(path, &cfg)
	return &cfg, err
}
