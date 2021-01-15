/*
Copyright © 2020 Avian Digital Forensics <sja@avian.dk>

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
	"context"
	"fmt"
	"os"

	"github.com/avian-digital-forensics/auto-processing/configs"
	"github.com/avian-digital-forensics/auto-processing/pkg/avian-client"
	"github.com/avian-digital-forensics/auto-processing/pkg/pretty"
	"github.com/avian-digital-forensics/auto-processing/pkg/utils"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

// serversCmd represents the servers command
//
// "avian servers"
var serversCmd = &cobra.Command{
	Use:   "servers",
	Short: "Servers for remote-connections",
	Long: `Servers handles all the servers available for remote-connections. 

Apply servers in your infrastructure to the backend,
list servers from the backend to see availability`,
}

// serversApplyCmd represents the apply servers command
//
// "avian servers apply <server.yml>"
var serversApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply new servers for remote-connections with specified config",
	Long: `Apply new servers for remote-connections with specified config. - For example: 
	
	avian servers apply servercfg.yml`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := applyServers(context.Background(), args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "could not apply servers to backend: %v\n", err)
		}
	},
}

// serversListCmd represents the list servers command
//
// "avian servers list"
var serversListCmd = &cobra.Command{
	Use:   "list",
	Short: "List servers available for remote-connection",
	Run: func(cmd *cobra.Command, args []string) {
		if err := listServers(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "could not list servers from backend: %v\n", err)
		}
	},
}

// srvService is needed by all server-commands
// to be able to speak to the API
var srvService *avian.ServerService

func init() {
	// Get the address for the API (where the avian service is listening at)
	address := os.Getenv("AVIAN_ADDRESS")
	if address == "" {
		ip, err := utils.GetIPAddress()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot get ip-address: %v", err)
			os.Exit(1)
		}
		address = ip
	}

	// Get the port for the API (where the avian service is listening at)
	port := os.Getenv("AVIAN_PORT")
	if port == "" {
		port = "8080"
	}

	// create the uri for the service
	url := fmt.Sprintf("http://%s:%s/oto/", address, port)

	// Set the client for the server-service
	// pass the uri and an empty token (since no token is needed)
	srvService = avian.NewServerService(avian.New(url, ""))

	// Add the commands to the correct hierarchy
	rootCmd.AddCommand(serversCmd)
	serversCmd.AddCommand(serversApplyCmd)
	serversCmd.AddCommand(serversListCmd)
}

// applyServers will apply the servers from the config-file
// to the service
func applyServers(ctx context.Context, path string) error {
	// get the config with the servers info
	cfg, err := configs.Get(path)
	if err != nil {
		return fmt.Errorf("Couldn't parse yml-file %s : %v", path, err)
	}

	// output that the service is testing connections to the applied servers
	fmt.Fprintf(os.Stdout, "INFO : Testing connection to servers\nPlease wait...\n")

	var count int
	for _, srv := range cfg.API.Servers {
		_, err := srvService.Apply(ctx, srv.Server)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "server: %s has been applied\n", srv.Server.Hostname)
		count++
	}

	fmt.Fprintf(os.Stdout, "applied %d servers to backend", count)
	return nil
}

// listServers lists all the servers
// that has been applied to the backend
func listServers(ctx context.Context) error {
	resp, err := srvService.List(ctx, avian.ServerListRequest{})
	if err != nil {
		return err
	}

	// format the response
	var headers table.Row
	var body []table.Row
	headers = table.Row{"ID", "Hostname", "Port", "OS", "Nuix-Path", "Status"}
	for _, s := range resp.Servers {
		status := "Inactive"
		if s.Active {
			status = "Active"
		}
		body = append(body, table.Row{s.ID, s.Hostname, s.Port, s.OperatingSystem, s.NuixPath, status})
	}

	fmt.Println(pretty.Format(headers, body))
	return nil
}
