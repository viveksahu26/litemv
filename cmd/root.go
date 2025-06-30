package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sbommv",
	Short: "sbommv is a CLI tool for transferring SBOMs between systems",
	Long:  `sbommv helps in transferring SBOMs from GitHub repositories to Interlynk or other systems.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
