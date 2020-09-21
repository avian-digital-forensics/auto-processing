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
	"net/http"
	"os"
	"time"

	"github.com/avian-digital-forensics/auto-processing/cmd/avian/cmd/queue"
	api "github.com/avian-digital-forensics/auto-processing/pkg/avian-api"
	"github.com/avian-digital-forensics/auto-processing/pkg/datastore/tables"
	"github.com/avian-digital-forensics/auto-processing/pkg/services"
	"github.com/avian-digital-forensics/auto-processing/pkg/utils"
	"github.com/gorilla/handlers"
	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/pacedotdev/oto/otohttp"
	ps "github.com/simonjanss/go-powershell"
	"github.com/simonjanss/go-powershell/backend"
	"github.com/spf13/cobra"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

// serviceCmd represents the service command
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
	address string // Address for http to listen on
	port    string // Port for http to listen on
	debug   bool   // To debug the service
	dbName  string // name for the SQLite-db
	logPath string // path for the log-files
)

// loggers
var (
	accessLogger  *lumberjack.Logger
	serviceLogger *lumberjack.Logger
)

func init() {
	rootCmd.AddCommand(serviceCmd)

	serviceCmd.Flags().StringVar(&address, "address", "0.0.0.0", "address to listen on")
	serviceCmd.Flags().StringVar(&port, "port", "8080", "port for HTTP to listen on")
	serviceCmd.Flags().BoolVar(&debug, "debug", false, "for debugging")
	serviceCmd.Flags().StringVar(&dbName, "db", "avian.db", "path to sqlite database")
	serviceCmd.Flags().StringVar(&logPath, "log-path", "./log/", "path to log-files")
}

func run() error {
	if err := setLoggers(); err != nil {
		return fmt.Errorf("failed to set lumberjack-loggers : %v", err)
	}

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(serviceLogger),
		zap.DebugLevel,
	)

	logger := zap.New(core, zap.Option(zap.WithCaller(debug)))
	defer logger.Sync()

	logger.Debug("Starting service", zap.Bool("debug", debug), zap.String("db", dbName), zap.String("log-path", logPath))

	// Set the server-address for HTTP
	if os.Getenv("AVIAN_ADDRESS") == "" {
		ip, err := utils.GetIPAddress()
		if err != nil {
			return fmt.Errorf("Cannot get ip-address: %v", err)
		}
		logger.Warn("No environment-variable found for: AVIAN_ADDRESS - using default", zap.String("default", address))
		address = ip
	} else {
		address = os.Getenv("AVIAN_ADDRESS")
	}

	// Set the server-port for HTTP
	if os.Getenv("AVIAN_PORT") == "" {
		logger.Warn("No environment-variable found for: AVIAN_PORT - using default", zap.String("default", port))
	} else {
		port = os.Getenv("AVIAN_PORT")
	}

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
	shell, err := ps.New(&backend.Local{})
	if err != nil {
		return fmt.Errorf("unable to create powershell-process : %v", err)
	}

	// start the queue
	logger.Info("Starting queue-service")
	queue := queue.New(db,
		shell,
		fmt.Sprintf("http://%s:%s/oto/", address, port),
		logger,
	)
	go queue.Start()

	// Create a oto-server
	logger.Debug("Creating oto http-server")
	server := otohttp.NewServer()

	// Register our services
	logger.Debug("Registering our oto http-services")
	api.RegisterServerService(server, services.NewServerService(db, shell, logger))
	api.RegisterNmsService(server, services.NewNmsService(db, logger))
	api.RegisterRunnerService(server, services.NewRunnerService(db, shell, logger, logPath))

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
	return srv.ListenAndServe()
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
