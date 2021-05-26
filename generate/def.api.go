package def

import (
	"time"

	"github.com/avian-digital-forensics/auto-processing/pkg/datastore"
	"github.com/avian-digital-forensics/auto-processing/pkg/inapp"
)

// ServerService handles all the servers
type ServerService interface {
	Apply(ServerApplyRequest) ServerApplyResponse
	List(ServerListRequest) ServerListResponse
}

// Server is the main struct for the
// servers.
type Server struct {
	// Base for the datastore
	datastore.Base

	// Hostname of the server.
	Hostname string

	// Port for the server.
	Port int64

	// OperatingSystem the server is running.
	OperatingSystem string

	// Username for connection to the server.
	Username string

	// Password for connection to the server.
	Password string

	// NuixPath to know where to run Nuix.
	NuixPath string

	// AvianScripts path to the avian-scripts.
	AvianScripts string

	// Active - if the server has an active job.
	Active bool
}

// ServerApplyRequest is the input-object
// for Apply in the server-service.
type ServerApplyRequest struct {
	Hostname        string
	Port            int64
	OperatingSystem string
	Username        string
	Password        string
	NuixPath        string
	AvianScripts    string
}

// ServerApplyResponse is the output-object
// for Apply in the server-service.
type ServerApplyResponse struct {
	Server Server
}

// ServerListRequest is the input-object
// for List in the server-service.
type ServerListRequest struct{}

// ServerListResponse is the output-object
// for List in the server-service.
type ServerListResponse struct {
	Servers []Server
}

// NmsService handles the Nuix Management Servers.
type NmsService interface {
	Apply(NmsApplyRequests) NmsApplyResponse
	List(NmsListRequest) NmsListResponse
	ListLicences(NmsListLicencesRequest) NmsListLicencesResponse
}

// Nms is the main struct for the Nuix Management Servers.
type Nms struct {
	// Base for the datastore.
	datastore.Base

	// Address of the nms-server
	// for example: license.avian.dk.
	Address string

	// Port for the nms-server.
	Port int64

	// Username for the nms-server.
	Username string

	// Password for the nms-server.
	Password string

	// Amount of workers licensed
	// to the server.
	Workers int64

	// Amount of workers in use.
	InUse int64

	// Licences available at the server.
	Licences []Licence

	// Is NMS a CLS relay server.
	IsRelay bool
}

// Licence holds information about licences
// in Nuix Management Server.
type Licence struct {
	// Base for the datastore.
	datastore.Base

	// Foreign-key for the NMS-server.
	NmsID uint

	// Type of licence.
	Type string

	// Amount of licences for this type.
	Amount int64

	// Amount of licenses in use for this type.
	InUse int64
}

// Licences is a holder for Licence.
type Licences struct {
	Licence LicenceApplyRequest
}

// LicenceApplyRequest is the input-object for
// applying NMS-licence.
type LicenceApplyRequest struct {
	// Type of licence.
	Type string

	// Amount of licences for this type.
	Amount int64
}

type NmsApplyRequests struct {
	Nms []NmsApplyRequest
}

// NmsApplyRequest is the input-object for
// Apply in the NMS-service.
type NmsApplyRequest struct {
	// Address of the nms-server
	// for example: license.avian.dk.
	Address string

	// Port for the nms-server.
	Port int64

	// Username for the nms-server.
	Username string

	// Password for the nms-server.
	Password string

	// Amount of workers licensed
	// to the nms-server.
	Workers int64

	// Licences available at the nms-server.
	Licences []Licences

	// Whether the NMS is a CLS relay server.
	IsRelay bool
}

// NmsApplyResponse is the output-object for
// Apply in the NMS-service.
type NmsApplyResponse struct {
	Nms []Nms
}

// NmsListRequest is the input-object for
// List in the NMS-service.
type NmsListRequest struct{}

// NmsListResponse is the output-object for
// List in the NMS-service.
type NmsListResponse struct {
	Nms []Nms
}

// NmsListLicencesRequest is the input-object for
// listing licences for a specific NMS.
type NmsListLicencesRequest struct {
	// ID for the nms-server
	// to list the licences for.
	NmsID uint
}

// NmsListLicencesResponse is the output-object for
// listing licences for a specific NMS.
type NmsListLicencesResponse struct {
	Licences []Licence
}

// RunnerService handles all the runners.
type RunnerService interface {
	// Apply applies the configuration to the backend.
	Apply(RunnerApplyRequest) RunnerApplyResponse

	// List returns the runners from the backend.
	List(RunnerListRequest) RunnerListResponse

	// Get returns the requested Runner
	Get(RunnerGetRequest) RunnerGetResponse

	// Delete deletes the requested Runner
	Delete(RunnerDeleteRequest) RunnerDeleteResponse

	// Start sets a runner to started
	Start(RunnerStartRequest) RunnerStartResponse

	// Failed sets a runner to failed
	Failed(RunnerFailedRequest) RunnerFailedResponse

	// Finish sets a runner to finished
	Finish(RunnerFinishRequest) RunnerFinishResponse

	// StartStage sets a stage to Active
	StartStage(StageRequest) StageResponse

	// FailedStage sets a stage to Failed
	FailedStage(StageRequest) StageResponse

	// FinishStage sets a stage to Finished
	FinishStage(StageRequest) StageResponse

	// LogItem logs an item
	LogItem(LogItemRequest) LogResponse

	// LogDebug logs a debug-message
	LogDebug(LogRequest) LogResponse

	// LogInfo logs an info-message
	LogInfo(LogRequest) LogResponse

	// LogError logs an error-message
	LogError(LogRequest) LogResponse

	// Heartbeat sends a heartbeat for the api
	Heartbeat(RunnerStartRequest) RunnerStartResponse

	// Script returns the script for the runner
	Script(RunnerGetRequest) RunnerScriptResponse

	UploadFile(UploadFileRequest) UploadFileResponse
}

// Runner holds the information for a specific runner
type Runner struct {
	// Base for the datastore
	datastore.Base

	// Name for the runner
	Name string

	// Server to use for the runner
	Hostname string

	// Nms to use for the runner
	Nms string

	// Licence to use for the runner
	Licence string

	// Xmx to use for the runner
	Xmx string

	// Amount of workers to use for the runner
	Workers int64

	// Active - if the runner is active or not
	Active bool

	// Status for the runner
	Status int64

	// HealthyAt - last time the runner was healthy
	HealthyAt *time.Time

	// CaseSettings for the cases to use
	CaseSettingsID uint
	CaseSettings   *CaseSettings

	// Stages for the runner
	Stages []*Stage

	// Switches to use for nuix-console
	Switches []*NuixSwitch

	CaseID string
}

// RunnerApplyRequest is the input-object for
// applying a runner-configuration to the Runner-service
type RunnerApplyRequest struct {
	// Name for the runner
	Name string

	// Server to use for the runner
	Hostname string

	// Nms to use for the runner
	Nms string

	// Licence to use for the runner
	Licence string

	// Xmx to use for the runner
	Xmx string

	// Amount of workers to use for the runner
	Workers int64

	// CaseSettings is the settings for the cases
	// that should be processed if Process-stage is used
	CaseSettings *CaseSettings

	// Stages for the runner
	Stages []*Stage

	// Switches to use for nuix-console
	Switches []string

	// Update - if the runner should be updated
	Update bool
}

// RunnerApplyResponse is the output-object for
// applying a runner-configuration to the backend
type RunnerApplyResponse struct {
	Runner Runner
}

// RunnerListRequest is the input-object for
// listing the runners from the backend
type RunnerListRequest struct{}

// RunnerListResponse is the input-object for
// listing the runners from the backend
type RunnerListResponse struct {
	Runners []Runner
}

// RunnerGetRequest is the input-object
// for requesting a runner by name
type RunnerGetRequest struct {
	Name string
}

// RunnerGetResponse is the output-object
// for requesting a runner by name
type RunnerGetResponse struct {
	Runner Runner
}

// RunnerDeleteRequest is the input-object
// for deleting a runner by name
type RunnerDeleteRequest struct {
	// Name of the runner
	Name string

	// DeleteCase - if the user wants
	// to delete the case for the runner
	DeleteCase bool

	// DeleteAllCases - if the user
	// wants to delete all cases for the runner
	DeleteAllCases bool

	// Force - if the delete should be forced
	Force bool
}

// RunnerDeleteResponse is the output-object
// for deleting a runner by name
type RunnerDeleteResponse struct{}

// RunnerScriptResponse is the output-object
// for GetScript
type RunnerScriptResponse struct {
	Script string
}

// RunnerStartRequest is the input-object
// for starting a runner by id
type RunnerStartRequest struct {
	ID     uint
	Runner string
	CaseID string
}

// RunnerStartResponse is the output-object
// for starting a runner by id
type RunnerStartResponse struct{}

// RunnerFailedRequest is the input-object
// for failing a runner by id
type RunnerFailedRequest struct {
	ID        uint
	Runner    string
	Exception string
}

// RunnerFailedResponse is the output-object
// for failing a runner by id
type RunnerFailedResponse struct{}

// RunnerFinishRequest is the input-object
// for finishing a runner by id
type RunnerFinishRequest struct {
	ID     uint
	Runner string
}

// RunnerFinishResponse is the output-object
// for finishing a runner by id
type RunnerFinishResponse struct{}

// NuixSwitch is a command argument for
// nuix-console
type NuixSwitch struct {
	datastore.Base
	RunnerID uint
	Value    string
}

type LogItemRequest struct {
	Runner       string
	Stage        string
	StageID      int
	Message      string
	Count        int
	MimeType     string
	GUID         string
	ProcessStage string
	IsCorrupted  bool
	IsDeleted    bool
	IsEncrypted  bool
}

type LogRequest struct {
	Runner    string
	Stage     string
	StageID   int
	Message   string
	Exception string
}

type LogResponse struct{}

// CaseSettings holds information about the cases
// if Processing-stage is used for a Runner
type CaseSettings struct {
	// Base for the datastore
	datastore.Base

	// CaseLocation is the parent-folder
	// for all cases
	CaseLocation string

	// Case holds the information for the single-case
	CaseID uint // foreign-key
	Case   *Case

	// CompoundCase holds the information for the compound-case
	CompoundCaseID uint // foreign-key
	CompoundCase   *Case

	// ReviewCompound holds the information for the review-compound
	ReviewCompoundID uint // foreign-key
	ReviewCompound   *Case
}

// Case holds the information for a case
type Case struct {
	// Base for the datastore
	datastore.Base

	// Name of the case
	Name string

	// Directory of the case
	Directory string

	// Description of the case
	Description string

	// Investigator of the case
	Investigator string

	ElasticSearchID uint
	ElasticSearch   *Elasticsearch
}

type Elasticsearch struct {
	datastore.Base
	ClusterName           string
	NuixTransportHost     string
	IndexNumberOfReplicas int
	IndexNumberOfShards   int
}

type StageRequest struct {
	Runner  string
	StageID uint
}

type StageResponse struct {
	Stage Stage
}

// Stage holds different types of stages for a Runner
type Stage struct {
	// Base for the datastore
	datastore.Base

	// Foreign-key for runners
	RunnerID uint

	// Index for where the stage where indexed in the yaml
	Index uint

	// Process-stage processes data into a Nuix-case
	Process *Process

	// SearchAndTag searches and tags data in a Nuix-case
	SearchAndTag *SearchAndTag

	// Populate populates data based on a search in a Nuix-case
	Populate *Populate

	// Ocr performs OCR based on a search in a Nuix-case
	Ocr *Ocr

	// Exclude excludes items in a Nuix-case based on a search
	Exclude *Exclude

	// Reload reloads items in a Nuix-case based on a search
	Reload *Reload

	// InApp is a stage for avian in-app scripts
	InApp *InApp

	// SyncDescendants syncs descendants for the specified items
	SyncDescendants *SyncDescendants

	// ScanNewChildItems scans for new child items based on a search
	ScanNewChildItems *ScanNewChildItems
}

// Process -stage processes data into a Nuix-case
type Process struct {
	// Base for the datastore
	datastore.Base

	// Foreign-key for stage
	StageID uint

	// Profile for the processor
	Profile ProcessingProfile

	// EvidenceStore to process to the nuix-case
	EvidenceStore []*Evidence

	// Status for the stage
	Status int64
}

type ProcessingProfile struct {
	// Base for the datastore
	datastore.Base

	// Original path given in runner config.
	Path string

	// Unique generated name for processing profile.
	Name string
}

// Evidence holds information about a specific evidence
type Evidence struct {
	// Base for the datastore
	datastore.Base

	// ProcessID foreign-key for process-table
	ProcessID uint

	// Name of the evidence
	Name string

	// Directory of where the evidence is located
	Directory string

	// Description of the evidence
	Description string

	// Encoding for the evidence (used when processing)
	Encoding string

	// TimeZone for the evidence
	TimeZone string

	// Custodian for the evidence
	Custodian string

	// Locale for the evidence (used when processing)
	Locale string
}

// SearchAndTag searches and tags data in a Nuix-case
type SearchAndTag struct {
	// Base for the datastore
	datastore.Base

	// StageID foreign-key for stage-table
	StageID uint

	// Search query in the case
	Search string

	// Tag for the items from the search
	Tag string

	// Files for the search-and-tag
	Files []*File

	// Status for the stage
	Status int64
}

// Populate populates data based on a search in a Nuix-case
type Populate struct {
	// Base for the datastore
	datastore.Base

	// StageID foreign-key for stage-table
	StageID uint

	// Search query in the case
	Search string
	// Types for the items to populate
	Types []*Type
	// Status for the stage
	Status int64
}

// Type holds information for a type
type Type struct {
	// Base for the datastore
	datastore.Base

	// PopulateID foreign-key for populate-table
	PopulateID uint

	// Type-name
	Type string

	// Status for the stage
	Status int64
}

// Ocr performs OCR based on a search in a Nuix-case
type Ocr struct {
	// Base for the datastore
	datastore.Base

	// StageID foreign-key for stage-table
	StageID uint

	// Profile for the ocr-processor
	Profile     string
	ProfilePath string

	// Search query in the case
	Search string

	// BatchSize for items
	BatchSize int

	// Status for the stage
	Status int64
}

// Exclude excludes items in a Nuix-case based on a search
type Exclude struct {
	// Base for the datastore
	datastore.Base

	// StageID foreign-key for stage-table
	StageID uint

	// Search query in the case
	Search string

	// Reason to exclude the items from the search
	Reason string

	// Status for the stage
	Status int64
}

// Reload reloads items in a Nuix-case based on a search
type Reload struct {
	// Base for the datastore
	datastore.Base

	// StageID foreign-key for stage-table
	StageID uint

	// Profile for the reload-processing
	Profile ProcessingProfile

	// Search query in the case
	Search string

	// Status for the stage
	Status int64
}

// File holds information about a file
type File struct {
	// Base for the datastore
	datastore.Base

	// SearchAndTagID foreign-key for searchandtag-table
	SearchAndTagID uint

	// Path for where the file is located at
	Path string
}

// InApp script as a stage
type InApp struct {
	// Base for the datastore
	datastore.Base

	// StageID foreign-key for stage-table
	StageID uint

	// Name for in-app script
	Name string

	// Config for in-app script
	Config string

	// Settings decoded from the
	// config-file provided in Config-field
	Settings inapp.Settings

	// Status for the stage
	Status int64
}

type SyncDescendants struct {
	// Base for the datastore
	datastore.Base

	// StageID foreign-key for stage-table
	StageID uint

	// Search for the items to sync
	Search string

	// Status for the stage
	Status int64
}

type ScanNewChildItems struct {
	// Base for the datastore
	datastore.Base

	// StageID foreign-key for stage-table
	StageID uint

	// Profile for processing
	Profile string

	// Search for the items to sync
	Search string

	// Status for the stage
	Status int64
}

type UploadFileRequest struct {
	Name        string
	Description string
	Content     []byte
}

type UploadFileResponse struct {
	Path string
}
