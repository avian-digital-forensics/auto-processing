package configs

import (
	"errors"
	"fmt"
	"os"
	"strings"

	avian "github.com/avian-digital-forensics/auto-processing/pkg/avian-client"

	"gopkg.in/yaml.v2"
)

// defines the yaml config
type Config struct {
	API API `yaml:"api"`
}

// defines the api
type API struct {
	Servers []Servers                `yaml:"servers"`
	Nms     avian.NmsApplyRequests   `yaml:"nmsApply"`
	Runner  avian.RunnerApplyRequest `yaml:"runner"`
}

// defines the servers config
type Servers struct {
	Server avian.ServerApplyRequest `yaml:"server"`
}

func ValidateRunnerConfig(r avian.RunnerApplyRequest) error {
	if r.CaseSettings == nil {
		return errors.New("specify caseSettings and caseLocation")
	}

	if r.CaseSettings.CaseLocation == "" {
		return errors.New("must specify caseLocation for caseSettings")
	}
	return nil
}

func PostprocessRunnerConfig(r avian.RunnerApplyRequest) avian.RunnerApplyRequest {
	if r.CaseSettings.Case == nil {
		r.CaseSettings.Case = &avian.Case{}
	}

	if r.CaseSettings.Case.Name == "" {
		r.CaseSettings.Case.Name = r.Name + "-single"
	}

	if r.CaseSettings.Case.Directory == "" {
		r.CaseSettings.Case.Directory = fmt.Sprintf("%s/%s-single",
			r.CaseSettings.CaseLocation,
			r.Name,
		)
	}

	//checks if compound case has been set
	if r.CaseSettings.CompoundCase == nil || r.CaseSettings.CompoundCase.Directory == "" {
		var compound_description string
		var compound_investigator string
		if r.CaseSettings.CompoundCase != nil {
			compound_description = r.CaseSettings.ReviewCompound.Description
			compound_investigator = r.CaseSettings.ReviewCompound.Investigator
		}

		r.CaseSettings.CompoundCase = &avian.Case{
			Name: r.Name + "-compound",
			Directory: fmt.Sprintf("%s/%s-compound",
				r.CaseSettings.CaseLocation,
				r.Name,
			),
			Description:  compound_description,
			Investigator: compound_investigator,
		}
	}

	//checks if review case has been set
	if r.CaseSettings.ReviewCompound == nil || r.CaseSettings.ReviewCompound.Directory == "" {
		var review_description string
		var review_investigator string
		if r.CaseSettings.ReviewCompound != nil {
			review_description = r.CaseSettings.ReviewCompound.Description
			review_investigator = r.CaseSettings.ReviewCompound.Investigator
		}

		r.CaseSettings.ReviewCompound = &avian.Case{
			Name: r.Name + "-review",
			Directory: fmt.Sprintf("%s/%s-review",
				r.CaseSettings.CaseLocation,
				r.Name,
			),
			Description:  review_description,
			Investigator: review_investigator,
		}
	}

	r.Name = strings.ToLower(r.Name)

	return r
}

// decodes and reads the yaml
func readYAML(path string, cfg *Config) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := yaml.NewDecoder(file)
	return decoder.Decode(cfg)
}

// Get returns data from yml file specified as path
func Get(path string) (*Config, error) {
	var cfg Config
	err := readYAML(path, &cfg)
	return &cfg, err
}
