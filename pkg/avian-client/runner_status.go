package avian

import api "github.com/avian-digital-forensics/auto-processing/pkg/avian-api"

const (
	StatusWaiting  int64 = 0
	StatusRunning  int64 = 1
	StatusFailed   int64 = 2
	StatusFinished int64 = 3
	StatusTimeout        = 4
)

func Status(status int64) string { return getStatus(status) }

func getStatus(status int64) string {
	if status == StatusWaiting {
		return "Waiting"
	}
	if status == StatusRunning {
		return "Running"
	}
	if status == StatusFailed {
		return "Failed"
	}
	if status == StatusFinished {
		return "Finished"
	}
	if status == StatusTimeout {
		return "Timeout"
	}
	return "Unknown"
}

func StageState(s *api.Stage) int64 {
	if s.Process != nil {
		return s.Process.Status
	}

	if s.SearchAndTag != nil {
		return s.SearchAndTag.Status
	}

	if s.Ocr != nil {
		return s.Ocr.Status
	}

	if s.Exclude != nil {
		return s.Exclude.Status
	}

	if s.Reload != nil {
		return s.Reload.Status
	}

	if s.Populate != nil {
		return s.Populate.Status
	}

	if s.InApp != nil {
		return s.InApp.Status
	}

	return 0
}

func (s *Stage) Status() string {
	if s.Process != nil {
		return getStatus(s.Process.Status)
	}

	if s.SearchAndTag != nil {
		return getStatus(s.SearchAndTag.Status)
	}

	if s.Ocr != nil {
		return getStatus(s.Ocr.Status)
	}

	if s.Exclude != nil {
		return getStatus(s.Exclude.Status)
	}

	if s.Reload != nil {
		return getStatus(s.Reload.Status)
	}

	if s.Populate != nil {
		return getStatus(s.Populate.Status)
	}

	if s.InApp != nil {
		return getStatus(s.InApp.Status)
	}

	return "Unknown"
}

func Name(s *api.Stage) string {
	if s.Process != nil {
		return "Process"
	}

	if s.SearchAndTag != nil {
		return "SearchAndTag"
	}

	if s.Ocr != nil {
		return "OCR"
	}

	if s.Exclude != nil {
		return "Exclude"
	}

	if s.Reload != nil {
		return "Reload"
	}

	if s.Populate != nil {
		return "Populate"
	}

	if s.InApp != nil {
		return "InApp-" + s.InApp.Name
	}

	return "Unknown"
}

func (s *Stage) Name() string {
	if s.Process != nil {
		return "Process"
	}

	if s.SearchAndTag != nil {
		return "SearchAndTag"
	}

	if s.Ocr != nil {
		return "OCR"
	}

	if s.Exclude != nil {
		return "Exclude"
	}

	if s.Reload != nil {
		return "Reload"
	}

	if s.Populate != nil {
		return "Populate"
	}

	if s.InApp != nil {
		return "InApp-" + s.InApp.Name
	}

	return "Unknown"
}

func Finished(status int64) bool { return status == StatusFinished }

func SetStatusRunning(stage *api.Stage) {
	if stage.Process != nil {
		stage.Process.Status = StatusRunning
	} else if stage.SearchAndTag != nil {
		stage.SearchAndTag.Status = StatusRunning
	} else if stage.Reload != nil {
		stage.Reload.Status = StatusRunning
	} else if stage.Exclude != nil {
		stage.Exclude.Status = StatusRunning
	} else if stage.Populate != nil {
		stage.Populate.Status = StatusRunning
	} else if stage.Ocr != nil {
		stage.Ocr.Status = StatusRunning
	} else if stage.InApp != nil {
		stage.InApp.Status = StatusRunning
	}
	return
}

func SetStatusFailed(stage *api.Stage) {
	if stage.Process != nil {
		stage.Process.Status = StatusFailed
	} else if stage.SearchAndTag != nil {
		stage.SearchAndTag.Status = StatusFailed
	} else if stage.Reload != nil {
		stage.Reload.Status = StatusFailed
	} else if stage.Exclude != nil {
		stage.Exclude.Status = StatusFailed
	} else if stage.Populate != nil {
		stage.Populate.Status = StatusFailed
	} else if stage.Ocr != nil {
		stage.Ocr.Status = StatusFailed
	} else if stage.InApp != nil {
		stage.InApp.Status = StatusFailed
	}
}

func SetStatusFinished(stage *api.Stage) {
	if stage.Process != nil {
		stage.Process.Status = StatusFinished
	} else if stage.SearchAndTag != nil {
		stage.SearchAndTag.Status = StatusFinished
	} else if stage.Reload != nil {
		stage.Reload.Status = StatusFinished
	} else if stage.Exclude != nil {
		stage.Exclude.Status = StatusFinished
	} else if stage.Populate != nil {
		stage.Populate.Status = StatusFinished
	} else if stage.Ocr != nil {
		stage.Ocr.Status = StatusFinished
	} else if stage.InApp != nil {
		stage.InApp.Status = StatusFinished
	}
}

func HasFinished(s *api.Stage) bool {
	if s.Process != nil {
		return Finished(s.Process.Status)
	} else if s.SearchAndTag != nil {
		return Finished(s.SearchAndTag.Status)
	} else if s.Reload != nil {
		return Finished(s.Reload.Status)
	} else if s.Exclude != nil {
		return Finished(s.Exclude.Status)
	} else if s.Populate != nil {
		return Finished(s.Populate.Status)
	} else if s.Ocr != nil {
		return Finished(s.Ocr.Status)
	} else if s.InApp != nil {
		return Finished(s.InApp.Status)
	}
	return false
}

func (s *Stage) Nil() bool {
	if s.Process != nil {
		return false
	} else if s.SearchAndTag != nil {
		return false
	} else if s.Reload != nil {
		return false
	} else if s.Exclude != nil {
		return false
	} else if s.Populate != nil {
		return false
	} else if s.Ocr != nil {
		return false
	} else if s.InApp != nil {
		return false
	}
	return true
}
