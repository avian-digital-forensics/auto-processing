/*
Copyright © 2020 AVIAN DIGITAL FORENSICS <sja@avian.dk>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/avian-digital-forensics/auto-processing/cmd/avian/cmd/heartbeat"
	"github.com/avian-digital-forensics/auto-processing/cmd/avian/cmd/queue"
	api "github.com/avian-digital-forensics/auto-processing/pkg/avian-api"
	"github.com/avian-digital-forensics/auto-processing/pkg/datastore/tables"
	"github.com/avian-digital-forensics/auto-processing/pkg/logging"
	"github.com/avian-digital-forensics/auto-processing/pkg/pwsh"
	"github.com/avian-digital-forensics/auto-processing/pkg/services"
	"github.com/gorilla/handlers"
	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sys/windows"

	"github.com/pacedotdev/oto/otohttp"
	"github.com/spf13/cobra"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

// serviceCmd represents the service command
//
// this will be executed when the user runs
// "avian service"
var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "HTTP-service for the queuing component",
	Long: `A http-service for the queue that communicates
with the backend and the running Nuix-scripts.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := run(); err != nil {
			fmt.Fprintf(os.Stderr, "could not start backend-service: %v\n", err)
		}
	},
}

// variables from flags
var (
	address  string // Address for http to listen on
	port     string // Port for http to listen on
	debug    bool   // To debug the service
	dbName   string // name for the SQLite-db
	logPath  string // path for the log-files
	verbose  bool   // Used to log to the console
	dataPath string // path for data
)

// loggers
var (
	accessLogger  *lumberjack.Logger
	serviceLogger *lumberjack.Logger
)

func init() {
	// add the service command to the root
	// (so it will be executable)
	rootCmd.AddCommand(serviceCmd)

	// get the working directory
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	// parse the flags (cli args)
	serviceCmd.Flags().StringVar(&address, "address", "0.0.0.0", "address to listen on")
	serviceCmd.Flags().StringVar(&port, "port", "8080", "port for HTTP to listen on")
	serviceCmd.Flags().BoolVar(&debug, "debug", false, "for debugging")
	serviceCmd.Flags().StringVar(&dbName, "db", "avian.db", "path to sqlite database")
	serviceCmd.Flags().StringVar(&logPath, "log-path", "./log/", "path to log-files")
	serviceCmd.Flags().StringVar(&dataPath, "data-path", wd, "path to raw-data")
	serviceCmd.Flags().BoolVar(&verbose, "verbose", false, "for logging to the console")
}

func run() error {
	// check that the service is run as admin
	if ok, err := isAdmin(); !ok {
		if err != nil {
			return fmt.Errorf("service must run as admin: %v", err)
		}
		return fmt.Errorf("service must run as admin")
	}

	// set loggers to the service
	if err := setLoggers(); err != nil {
		return fmt.Errorf("failed to set lumberjack-loggers : %v", err)
	}

	if strings.HasPrefix(dataPath, ".") {
		return fmt.Errorf("specify full path for data-path")
	}

	// fix paths from flags
	logPath = fixPath(logPath)
	dataPath = fixPath(dataPath)

	// make sure dataPath exists
	if _, err := os.Stat(dataPath); os.IsNotExist(err) {
		if err := os.Mkdir(dataPath, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create dataPath: %v", dataPath)
		}
	}

	// create a core for the zap-logger
	consoleConfig := zap.NewProductionEncoderConfig()
	consoleConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(consoleConfig),
		zapcore.AddSync(serviceLogger),
		zap.DebugLevel,
	)

	// if the verbose-flag is used
	// set consoleConfig to the core
	if verbose {
		core = zapcore.NewTee(core, zapcore.NewCore(
			zapcore.NewConsoleEncoder(consoleConfig),
			zapcore.AddSync(os.Stdout),
			zap.DebugLevel,
		))
	}

	// Create the zap-logger with the core
	logger := zap.New(core, zap.Option(zap.WithCaller(debug)))
	defer logger.Sync()

	logger.Debug("Starting service", zap.Bool("debug", debug), zap.String("db", dbName), zap.String("log-path", logPath))

	// Create a log-handler
	logHandler := logging.New(logPath)
	go func() {
		// Clean the unused logs every hour
		cleanAt := time.Hour * 1
		for {
			time.Sleep(cleanAt)
			logHandler.Clean(time.Now().Add(-cleanAt))
		}
	}()

	// Set the server-address for HTTP
	if os.Getenv("AVIAN_ADDRESS") != "" {
		address = os.Getenv("AVIAN_ADDRESS")
	}

	// Set the server-port for HTTP
	if os.Getenv("AVIAN_PORT") != "" {
		port = os.Getenv("AVIAN_PORT")
	}

	serviceURI := fmt.Sprintf("http://%s:%s/oto/", address, port)

	// Connect to the database
	logger.Info("Connecting to database")
	db, err := gorm.Open("sqlite3", dbName)
	if err != nil {
		return fmt.Errorf("failed to connect database : %v", err)
	}

	// If debug is true, enable logmode
	db.LogMode(debug)

	// Migrate the db-tables
	logger.Info("Migrating db-tables")
	if err := tables.Migrate(db); err != nil {
		return err
	}

	// Index the db-tables
	logger.Info("Creating db-indexes")
	if err := tables.Index(db); err != nil {
		return err
	}

	// Create a powershell-shell for remote connections
	logger.Info("Creating powershell-process for remote-connections")
	shell, err := pwsh.New()
	if err != nil {
		return fmt.Errorf("unable to create powershell-process : %v", err)
	}

	// start the queue (queue handles when the runners should start)
	logger.Info("Starting queue-service")
	queue := queue.New(db,
		shell,
		serviceURI,
		logger,
	)
	go queue.Start()

	// Create a oto-server
	logger.Debug("Creating oto http-server")
	server := otohttp.NewServer()

	// Register our services
	logger.Debug("Registering our oto http-services")
	runnersvc := services.NewRunnerService(db, shell, logger, logHandler, serviceURI, dataPath)
	api.RegisterRunnerService(server, runnersvc)
	api.RegisterServerService(server, services.NewServerService(db, shell, logger))
	api.RegisterNmsService(server, services.NewNmsService(db, logger))

	logger.Debug("Starting heartbeat-service")
	heartbeat := heartbeat.New(runnersvc, logger)
	go heartbeat.Beat()

	// Handle our oto-server @ /oto
	logger.Debug("Handle oto @ /oto/")
	http.Handle("/oto/", server)

	// Wrap the http-server with the accesslogger
	loggedServer := handlers.LoggingHandler(accessLogger, server)

	// Create our CORS-handlers
	corsOrigins := handlers.AllowedOrigins([]string{"*"})
	corsMethods := handlers.AllowedMethods([]string{"HEAD", "POST", "GET", "DELETE", "PATCH", "PUT", "OPTIONS"})
	corsHeaders := handlers.AllowedHeaders([]string{
		"Accept",
		"Authorization",
		"Content-Type",
		"User-Agent",
	})

	// Create our HTTP-server
	srv := &http.Server{
		Handler: handlers.CORS(corsOrigins, corsMethods, corsHeaders)(loggedServer),
		Addr:    fmt.Sprintf("%s:%s", address, port),
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	logger.Info("http-service listening", zap.String("address", address), zap.String("port", port))
	if !verbose {
		log.Printf("http-service listening @ %s:%s", address, port)
	}

	if err := srv.ListenAndServe(); err != nil {
		logger.Error("cannot start http-server", zap.String("address", address), zap.String("port", port), zap.String("exception", err.Error()))
		return err
	}
	return nil
}

func setLoggers() error {
	// Create log-path
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		if err := os.Mkdir(logPath, 0755); err != nil {
			return err
		}
	}

	// Create access-logfile
	accessLog, err := os.OpenFile(logPath+"access.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return fmt.Errorf("error opening file: %v", err)
	}

	// Create service-logfile
	serviceLog, err := os.OpenFile(logPath+"service.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return fmt.Errorf("error opening file: %v", err)
	}

	accessLogger = &lumberjack.Logger{
		Filename:   accessLog.Name(),
		MaxSize:    0, // megabytes
		MaxBackups: 3,
		MaxAge:     1, //days
	}

	serviceLogger = &lumberjack.Logger{
		Filename:   serviceLog.Name(),
		MaxSize:    0, // megabytes
		MaxBackups: 3,
		MaxAge:     1, //days
	}

	return nil
}

func lumberjackZapHook(e zapcore.Entry) error {
	serviceLogger.Write([]byte(fmt.Sprintf("%+v", e)))
	return nil
}

func isAdmin() (bool, error) {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false, fmt.Errorf("SID Error: %s", err)
	}

	defer windows.FreeSid(sid)
	token := windows.Token(0)

	member, err := token.IsMember(sid)
	if err != nil {
		return false, fmt.Errorf("Token Membership Error: %s", err)
	}
	return member, nil
}

func fixPath(path string) string {
	if strings.HasSuffix(path, "/") || strings.HasSuffix(path, "\\") {
		return path
	}

	if strings.Contains(path, ":\\") {
		return path + "\\"
	}

	return path + "/"
}
