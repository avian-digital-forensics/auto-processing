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

// nmsCmd represents the nms command
//
// "avian nms"
var nmsCmd = &cobra.Command{
	Use:   "nms",
	Short: "Handle the NMS-servers in your infrastructure for licences",
	Long: `NMS handles the Nuix Management Servers in your infrastructure, 
to keep track of licence-usage.`,
}

// nmsApplyCmd represents the apply command
//
// "avian nms apply <nms.yml>"
var nmsApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply new NMS-configuration",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := applyNms(context.Background(), args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "could not apply servers to backend: %v\n", err)
		}
	},
}

// nmsLicencesCmd represents the licences command
//
// "avian nms licences"
var nmsLicencesCmd = &cobra.Command{
	Use:   "licences",
	Short: "List licences for the specified nms (specify by address)",
	Run: func(cmd *cobra.Command, args []string) {
		if err := licencesNms(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "could not list licences from backend: %v\n", err)
		}
	},
}

// nmsListCmd represents the list command
//
// "avian nms list"
var nmsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List nms-servers from the backend",
	Run: func(cmd *cobra.Command, args []string) {
		if err := listNms(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "could not list servers from backend: %v\n", err)
		}
	},
}

var nmsService *avian.NmsService

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

	// set the client to the NmsService to speak to the API
	nmsService = avian.NewNmsService(avian.New(url, ""))

	rootCmd.AddCommand(nmsCmd)
	nmsCmd.AddCommand(nmsApplyCmd)
	nmsCmd.AddCommand(nmsListCmd)
	nmsCmd.AddCommand(nmsLicencesCmd)
}

// applyNms applies the specified nms-servers in the yaml-file
func applyNms(ctx context.Context, path string) error {
	// get the nms-config
	cfg, err := configs.Get(path)
	if err != nil {
		return fmt.Errorf("Couldn't parse yml-file %s : %v", path, err)
	}

	// send the request to the service
	resp, err := nmsService.Apply(ctx, cfg.API.Nms)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "applied %d nuix management servers to backend", len(resp.Nms))
	return nil
}

// listNms lists all the nms-servers from the service
func listNms(ctx context.Context) error {
	resp, err := nmsService.List(ctx, avian.NmsListRequest{})
	if err != nil {
		return err
	}

	var headers table.Row
	var body []table.Row
	headers = table.Row{"ID", "Address", "Port", "Workers", "In-Use"}
	for _, s := range resp.Nms {
		body = append(body, table.Row{s.ID, s.Address, s.Port, s.Workers, s.InUse})
	}

	fmt.Println(pretty.Format(headers, body))
	return nil
}

// licencesNms should list all the licences from the service
func licencesNms(ctx context.Context) error {
	resp, err := nmsService.List(ctx, avian.NmsListRequest{})
	if err != nil {
		return err
	}

	var headers table.Row
	var body []table.Row
	headers = table.Row{"ID", "Address", "Type", "Licences", "In-Use"}
	for _, s := range resp.Nms {
		for _, lic := range s.Licences {
			body = append(body, table.Row{lic.ID, s.Address, lic.Type, lic.Amount, lic.InUse})
		}
	}

	fmt.Println(pretty.Format(headers, body))
	return nil
}
