package log

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

func Get(source string) (*logrus.Entry, *os.File) {
	dt := time.Now()
	timestamp := dt.Format("20060102")
	filename := fmt.Sprintf("%s%s.log", source, timestamp)

	// create log-dir
	if _, err := os.Stat("./logs"); os.IsNotExist(err) {
		os.Mkdir("./logs", os.ModePerm)
	}

	// create log-file with read-write & create-permissions
	logFile, err := os.OpenFile("./logs/"+filename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Failed to open logfile: %v", err)
		os.Exit(2)
	}

	logger := &logrus.Logger{
		Out:       io.MultiWriter(os.Stdout, logFile),
		Level:     logrus.DebugLevel,
		Formatter: new(logrus.JSONFormatter),
	}
	log := logger.WithField("source", source)
	return log, logFile
}
