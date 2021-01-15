package logging

import (
	"fmt"
	"os"
	"time"

	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Service is the API for the logging
type Service interface {
	// Clean cleans the log-holders
	Clean(from time.Time)

	// Get gets a logger by name
	Get(name string) (*zap.Logger, error)
}

// svc holds the dependencies for the logging.Service
type svc struct {
	// LogPath is where the logs are stored
	LogPath string

	// Holder holds the loggers
	Holder map[string]*Logholder
}

// Logholder holds the dependencies
// for a logger
type Logholder struct {
	lastUsed time.Time
	lumber   *lumberjack.Logger
	logger   *zap.Logger
	file     *os.File
}

// New creates a new service
func New(logPath string) Service {
	return svc{
		LogPath: logPath,
		Holder:  make(map[string]*Logholder),
	}
}

// Clean the log-holder of inactive logs
// from a specified time
func (s svc) Clean(from time.Time) {
	for name, holder := range s.Holder {
		if holder.lastUsed.After(from) {
			// skip cleaning if the logger has been just after <from>
			continue
		}

		holder.logger = nil
		holder.lumber.Close()
		holder.lumber = nil
		holder.file.Close()
		holder.file = nil
		delete(s.Holder, name)
	}
}

// Get the specified log by name
// - if not in memory, it will be created/opened
func (s svc) Get(name string) (*zap.Logger, error) {
	if log, ok := s.Holder[name]; ok {
		log.lastUsed = time.Now()
		return log.logger, nil
	}

	return s.open(name)
}

// open will create or open the log specified by name
func (s svc) open(logName string) (*zap.Logger, error) {
	// open or create the log file
	log, err := os.OpenFile(s.LogPath+logName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, fmt.Errorf("error opening log-file %s: %v", logName, err)
	}

	lumberjackLogger := &lumberjack.Logger{
		Filename:   log.Name(),
		MaxSize:    0, // megabytes
		MaxBackups: 3,
		MaxAge:     1, //days
	}

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(lumberjackLogger),
		zap.DebugLevel,
	)

	logger := zap.New(core)
	s.Holder[logName] = &Logholder{
		lastUsed: time.Now(),
		logger:   logger,
		lumber:   lumberjackLogger,
		file:     log,
	}
	return logger, nil
}
