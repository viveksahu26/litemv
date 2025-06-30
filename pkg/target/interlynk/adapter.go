// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package interlynk

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/interlynk-io/sbommv/pkg/iterator"
	"github.com/interlynk-io/sbommv/pkg/logger"
	"github.com/interlynk-io/sbommv/pkg/sbom"
	"github.com/interlynk-io/sbommv/pkg/tcontext"
	"github.com/interlynk-io/sbommv/pkg/types"
	"github.com/interlynk-io/sbommv/pkg/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// InterlynkAdapter manages SBOM uploads to the Interlynk service.
type InterlynkAdapter struct {
	// Config fields
	ProjectName    string
	ProjectVersion string

	ProjectEnv string

	BaseURL string
	ApiKey  string
	Role    types.AdapterRole

	// HTTP client for API requests
	client         *http.Client
	settings       types.UploadSettings
	ProcessingMode types.ProcessingMode

	Overwrite bool
}

// AddCommandParams adds GitHub-specific CLI flags
func (i *InterlynkAdapter) AddCommandParams(cmd *cobra.Command) {
	cmd.Flags().String("out-interlynk-url", "https://api.interlynk.io/lynkapi", "Interlynk API URL")
	cmd.Flags().String("out-interlynk-project-name", "", "Interlynk Project Name")
	cmd.Flags().String("out-interlynk-project-env", "default", "Interlynk Project Environment")
}

// ParseAndValidateParams validates the Interlynk adapter params
func (i *InterlynkAdapter) ParseAndValidateParams(cmd *cobra.Command) error {
	var urlFlag, projectNameFlag, projectEnvFlag string
	var missingFlags []string
	var invalidFlags []string

	switch i.Role {

	case types.InputAdapterRole:
		return fmt.Errorf("The Interlynk adapter doesn't support input adapter functionalities.")

	case types.OutputAdapterRole:
		urlFlag = "out-interlynk-url"
		projectNameFlag = "out-interlynk-project-name"
		projectEnvFlag = "out-interlynk-project-env"

	default:
		return fmt.Errorf("The adapter is neither an input type nor an output type")
	}

	// validate flags for respective adapters
	err := utils.FlagValidation(cmd, types.InterlynkAdapterType, types.OutputAdapterFlagPrefix)
	if err != nil {
		return fmt.Errorf("interlynk flag validation failed: authentication required")
	}

	// Get flags
	url, _ := cmd.Flags().GetString(urlFlag)
	projectName, _ := cmd.Flags().GetString(projectNameFlag)
	projectEnv, _ := cmd.Flags().GetString(projectEnvFlag)

	// Check if INTERLYNK_SECURITY_TOKEN is set
	token := viper.GetString("INTERLYNK_SECURITY_TOKEN")
	if token == "" {
		return fmt.Errorf("missing INTERLYNK_SECURITY_TOKEN: authentication required")
	}

	// Validate Interlynk URL
	if !utils.IsValidURL(url) {
		invalidFlags = append(invalidFlags, fmt.Sprintf("invalid Interlynk API URL format: %s", url))
	}

	// Restrict `--out-interlynk-project-env` to only allowed values
	allowedEnvs := map[string]bool{"default": true, "development": true, "production": true}
	if !allowedEnvs[projectEnv] {
		invalidFlags = append(invalidFlags, fmt.Sprintf("invalid project environment: %s (allowed values: default, development, production)", projectEnv))
	}

	// Validate Interlynk connectivity before proceeding
	if err := ValidateInterlynkConnection(url, token); err != nil {
		return fmt.Errorf("Interlynk validation failed: %w", err)
	}

	// Show missing/invalid flags
	if len(missingFlags) > 0 {
		return fmt.Errorf("missing output adapter required flags: %v\n\nUse 'sbommv transfer --help' for usage details.", missingFlags)
	}
	if len(invalidFlags) > 0 {
		return fmt.Errorf("invalid output adapter flag usage:\n- %s\n\nUse 'sbommv transfer --help' for correct usage.", strings.Join(invalidFlags, "\n- "))
	}

	// Assign values to struct
	i.BaseURL = url
	i.ProjectName = projectName
	i.ProjectEnv = projectEnv
	i.ApiKey = token
	// i.settings = types.UploadSettings{ProcessingMode: types.UploadMode(i.ProcessingMode)}
	i.settings = types.UploadSettings{ProcessingMode: types.UploadMode(types.UploadSequential)}

	logger.LogDebug(cmd.Context(), "Interlynk parameters validated and assigned",
		"url", i.BaseURL,
		"project_name", i.ProjectName,
		"project_env", i.ProjectEnv,
		"overwrite", i.Overwrite,
		"processing_mode", i.settings.ProcessingMode,
		"role", i.Role,
	)
	return nil
}

// FetchSBOMs retrieves SBOMs lazily
func (i *InterlynkAdapter) FetchSBOMs(ctx tcontext.TransferMetadata) (iterator.SBOMIterator, error) {
	return nil, fmt.Errorf("Interlynk adapter does not support SBOM Fetching")
}

func (i *InterlynkAdapter) UploadSBOMs(ctx tcontext.TransferMetadata, iterator iterator.SBOMIterator) error {
	logger.LogDebug(ctx.Context, "Starting SBOM upload", "mode", i.settings.ProcessingMode)

	if i.settings.ProcessingMode != "sequential" {
		return fmt.Errorf("unsupported processing mode: %s", i.settings.ProcessingMode) // Future-proofed for parallel & batch
	}

	switch i.settings.ProcessingMode {

	case types.UploadParallel:
		// TODO: cuncurrent upload: As soon as we get the SBOM, upload it
		// i.uploadParallel()
		return fmt.Errorf("processing mode %q not yet implemented", i.settings.ProcessingMode)

	case types.UploadBatching:
		// TODO: hybrid of sequential + parallel
		// i.uploadBatch()
		return fmt.Errorf("processing mode %q not yet implemented", i.settings.ProcessingMode)

	case types.UploadSequential:
		// Sequential Processing: Fetch SBOM → Upload → Repeat
		i.uploadSequential(ctx, iterator)

	default:
		//
		return fmt.Errorf("invalid processing mode: %q", i.settings.ProcessingMode)
	}

	return nil
}

// uploadSequential handles sequential SBOM processing and uploading
func (i *InterlynkAdapter) uploadSequential(ctx tcontext.TransferMetadata, sboms iterator.SBOMIterator) error {
	logger.LogDebug(ctx.Context, "Uploading SBOMs in sequential mode")

	// Initialize Interlynk API client
	client := NewClient(Config{
		Token:       i.ApiKey,
		APIURL:      i.BaseURL,
		ProjectName: i.ProjectName,
		ProjectEnv:  i.ProjectEnv,
	})

	errorCount := 0
	maxRetries := 5
	totalSBOMs := 0
	successfullyUploaded := 0

	// space for proper logging
	fmt.Println()

	for {
		sbom, err := sboms.Next(ctx)
		if err == io.EOF {
			break
		}
		totalSBOMs++
		if err != nil {
			logger.LogInfo(ctx.Context, "error", err)
			errorCount++
			if errorCount >= maxRetries {
				break
			}
			continue
		}
		errorCount = 0 // Reset error counter on successful iteration

		logger.LogDebug(ctx.Context, "Uploading SBOM", "file", sbom.Path, "data size", len(sbom.Data))

		sourceAdapter := ctx.Value("source")

		finalProjectName, _ := utils.ConstructProjectName(ctx, client.ProjectName, client.ProjectVersion, sbom.Namespace, sbom.Version, sbom.Path, sbom.Data, sourceAdapter.(string))

		// if projectName == "" {
		// 	// THIS CASE OCCURS WHEN SBOM IS NOT IN JSON FORMAT
		// 	// when a JSON SBOM has empty primary comp and version, use the file name as project name
		// 	projectName = filepath.Base(sbom.Path)
		// 	projectName = projectName[:len(projectName)-len(filepath.Ext(projectName))]
		// 	projectVersion = "latest"
		// }
		// finalProjectName := fmt.Sprintf("%s-%s", projectName, projectVersion)

		projectID, projectName, err := client.FindOrCreateProjectGroup(ctx, finalProjectName)
		if err != nil {
			logger.LogInfo(ctx.Context, "error", err)
			continue
		}
		logger.LogDebug(ctx.Context, "SBOMs preparing to upload", "name", projectName, "id", projectID)

		// Upload SBOM content (stored in memory)
		err = client.UploadSBOM(ctx, projectID, sbom.Data)
		if err != nil {
			logger.LogInfo(ctx.Context, "error", "file", sbom.Path, "project name", projectName)
		} else {
			successfullyUploaded++
			logger.LogDebug(ctx.Context, "upload", "file", sbom.Path, "project name", projectName)
		}
		logger.LogInfo(ctx.Context, "upload", "success", true, "project", finalProjectName, "file", sbom.Path)

	}

	logger.LogInfo(ctx.Context, "upload", "sboms", totalSBOMs, "success", successfullyUploaded, "failed", errorCount)
	return nil
}

// DryRunUpload simulates SBOM upload to Interlynk without actual data transfer.
func (i *InterlynkAdapter) DryRun(ctx tcontext.TransferMetadata, sbomIterator iterator.SBOMIterator) error {
	logger.LogDebug(ctx.Context, "🔄 Dry-Run Mode: Simulating Upload to Interlynk...")

	// Step 1: Validate Interlynk Connection
	err := ValidateInterlynkConnection(i.BaseURL, i.ApiKey)
	if err != nil {
		return fmt.Errorf("interlynk flag validation failed: %w", err)
	}

	// Step 2: Initialize SBOM Processor
	processor := sbom.NewSBOMProcessor("", false)

	// Step 3: Organize SBOMs into Projects
	projectSBOMs := make(map[string][]sbom.SBOMDocument)
	totalSBOMs := 0
	uniqueFormats := make(map[string]struct{})

	for {
		sbom, err := sbomIterator.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.LogError(ctx.Context, err, "Error retrieving SBOM from iterator")
			continue
		}

		// Update processor with current SBOM data
		processor.Update(sbom.Data, sbom.Namespace, sbom.Path)

		// Process SBOM to extract metadata
		doc, err := processor.ProcessSBOMs()
		if err != nil {
			logger.LogError(ctx.Context, err, "Failed to process SBOM")
			continue
		}

		sourceAdapter := ctx.Value("source")

		finalProjectName, _ := utils.ConstructProjectName(ctx, i.ProjectName, i.ProjectVersion, sbom.Namespace, sbom.Version, sbom.Path, sbom.Data, sourceAdapter.(string))

		projectKey := fmt.Sprintf("%s", finalProjectName)
		projectSBOMs[projectKey] = append(projectSBOMs[projectKey], doc)
		totalSBOMs++
		uniqueFormats[string(doc.Format)] = struct{}{}
	}

	// Step 4: Print Dry-Run Summary
	fmt.Println("")
	fmt.Printf("📦 Interlynk API Endpoint: %s\n", i.BaseURL)
	fmt.Printf("📂 Project Groups Total: %d\n", len(projectSBOMs))
	fmt.Printf("📊 Total SBOMs to be Uploaded: %d\n", totalSBOMs)
	fmt.Printf("📦 INTERLYNK_SECURITY_TOKEN is valid\n")
	fmt.Printf("📦 Unique Formats: %s\n", formatSetToString(uniqueFormats))
	fmt.Println()

	// Step 5: Print Project Details
	for project, sboms := range projectSBOMs {
		fmt.Printf("📌 Project: %s → %d SBOMs\n", project, len(sboms))
		for _, doc := range sboms {
			fmt.Printf("   - 📁  | Format: %s | SpecVersion: %s | Size: %d KB | Filename: %s\n",
				doc.Format, doc.SpecVersion, len(doc.Content)/1024, doc.Filename)
		}
	}

	fmt.Println("\n✅ Dry-run completed. No data was uploaded to Interlynk.")
	return nil
}
