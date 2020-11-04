/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

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

const (
	RunnerWaiting  = 0
	RunnerRunning  = 1
	RunnerFailed   = 2
	RunnerFinished = 3
)

// runnerCmd represents the runner command
var runnersCmd = &cobra.Command{
	Use:   "runners",
	Short: "Runners are the automated workflow for Nuix",
}

// runnerApplyCmd represents the servers command
var runnersApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply new runner for Nuix",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := applyRunner(context.Background(), args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "could not apply runner to backend: %v\n", err)
		}
	},
}

// runnerListCmd represents the servers command
var runnersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the runners",
	Run: func(cmd *cobra.Command, args []string) {
		if err := listRunners(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "could not list runners from backend: %v\n", err)
		}
	},
}

// runnerStagesCmd represents the servers command
var runnerStagesCmd = &cobra.Command{
	Use:   "stages",
	Short: "List the stages for the specified runner (specified by name)",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := stagesRunner(context.Background(), args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "could not get stages for runner from backend: %v\n", err)
		}
	},
}

// runnerDeleteCmd represents the delete runner command
var runnerDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "List the stages for the specified runner (specified by name)",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := deleteRunner(context.Background(), args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "could not delete runner from backend: %v\n", err)
		}
	},
}

// runnerScriptCmd represents the delete runner command
var runnerScriptCmd = &cobra.Command{
	Use:   "script",
	Short: "Returns the script for the specified runner (specified by name)",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := scriptRunner(context.Background(), args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "could not get the script for runner from backend: %v\n", err)
		}
	},
}

var (
	runnerService *avian.RunnerService
	forceDelete   bool
	forceApply    bool
)

func init() {
	address := os.Getenv("AVIAN_ADDRESS")
	if address == "" {
		ip, err := utils.GetIPAddress()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot get ip-address: %v", err)
			os.Exit(1)
		}
		address = ip
	}

	port := os.Getenv("AVIAN_PORT")
	if port == "" {
		port = "8080"
	}
	url := fmt.Sprintf("http://%s:%s/oto/", address, port)

	runnerService = avian.NewRunnerService(avian.New(url, "hej"))

	rootCmd.AddCommand(runnersCmd)
	runnersCmd.AddCommand(runnersApplyCmd)
	runnersCmd.AddCommand(runnersListCmd)
	runnersCmd.AddCommand(runnerStagesCmd)
	runnersCmd.AddCommand(runnerDeleteCmd)
	runnersCmd.AddCommand(runnerScriptCmd)
	runnerDeleteCmd.Flags().BoolVar(&forceDelete, "force", false, "force deleting an active runner")
	runnersApplyCmd.Flags().BoolVar(&forceApply, "force", false, "force applying a runner")
}

func applyRunner(ctx context.Context, path string) error {
	cfg, err := configs.Get(path)
	if err != nil {
		return fmt.Errorf("Couldn't parse yml-file %s : %v", path, err)
	}

	runner, err := configs.SetCaseSettings(cfg.API.Runner)
	if err != nil {
		return err
	}

	runner.Update = forceApply
	resp, err := runnerService.Apply(ctx, runner)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Runner: %s has been applied", resp.Runner.Name)
	return nil
}

func listRunners(ctx context.Context) error {
	resp, err := runnerService.List(ctx, avian.RunnerListRequest{})
	if err != nil {
		return err
	}

	var headers table.Row
	var body []table.Row
	headers = table.Row{"ID", "Runner", "Host", "Nms", "Licencetype", "Workers", "Status", "Stage"}
	for _, r := range resp.Runners {
		var status string
		var stage string
		for _, s := range r.Stages {
			stage = s.Name()
			status = s.Status()

			// Break if the stage is running
			if status == "Running" {
				break
			}

			if status == "Failed" {
				break
			}

			// Break if the stage is waiting
			if status == "Waiting" {
				break
			}
		}
		body = append(body, table.Row{r.ID, r.Name, r.Hostname, r.Nms, r.Licence, r.Workers, avian.Status(r.Status), stage})
	}

	fmt.Fprintf(os.Stdout, "%s\n", pretty.Format(headers, body))
	return nil
}

func stagesRunner(ctx context.Context, runner string) error {
	resp, err := runnerService.Get(ctx, avian.RunnerGetRequest{Name: runner})
	if err != nil {
		return err
	}

	var headers table.Row
	var body []table.Row
	headers = table.Row{"ID", "Runner", "Stage", "Status"}

	for _, s := range resp.Runner.Stages {
		if !s.Nil() {
			body = append(body, table.Row{s.ID, resp.Runner.Name, s.Name(), s.Status()})
		}
	}

	fmt.Fprintf(os.Stdout, "%s\n", pretty.Format(headers, body))
	return nil
}

func deleteRunner(ctx context.Context, runner string) error {
	_, err := runnerService.Delete(ctx, avian.RunnerDeleteRequest{Name: runner, Force: forceDelete})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Runner: %s has been deleted", runner)
	return nil
}

func scriptRunner(ctx context.Context, runner string) error {
	resp, err := runnerService.Script(ctx, avian.RunnerGetRequest{Name: runner})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "%s", resp.Script)
	return nil
}
