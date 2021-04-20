package inapp

import (
	"io/ioutil"
)

type Settings struct {
	SettingsFile string `yaml:"settings_file" json:"settings_file,omitempty"`
}

func Config(path string, cfg *Settings) error {
	/*file, err := os.Open(path)
	if err != nil {
		return err
	}*/

	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	cfg.SettingsFile = string(bytes)
	return nil
}
