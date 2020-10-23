package inapp

import (
	"os"

	"gopkg.in/yaml.v2"
)

type Settings struct {
	ArchivedPrefix                     string `yaml:"archived_prefix" json:"archived_prefix"`
	ArchivedTag                        string `yaml:"archived_tag" json:"archived_tag"`
	ArchivedHasDuplicateTag            string `yaml:"archived_has_duplicate_tag" json:"archived_has_duplicate_tag"`
	ArchivedMissingDuplicateTag        string `yaml:"archived_missing_duplicate_tag" json:"archived_missing_duplicate_tag"`
	HasMissingAttachmentsTag           string `yaml:"has_missing_attachments_tag" json:"has_missing_attachments_tag"`
	ExcludeArchivedItemsWithDuplicates string `yaml:"exclude_archived_items_with_duplicates" json:"exclude_archived_items_with_duplicates"`
	MainDirectory                      string `yaml:"main_directory" json:"main_directory"`
	MetadataKey                        string `yaml:"metadata_key" json:"metadata_key"`
	SourcePath                         string `yaml:"source_path" json:"source_path"`
}

func Config(path string, cfg *Settings) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := yaml.NewDecoder(file)
	return decoder.Decode(cfg)
}
