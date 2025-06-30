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

package github

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/interlynk-io/sbommv/pkg/logger"
	"github.com/interlynk-io/sbommv/pkg/tcontext"
)

// SupportedTools maps tool names to their GitHub repositories
var SupportedTools = map[string]string{
	"syft":    "https://github.com/anchore/syft.git",
	"spdxgen": "https://github.com/spdx/spdx-sbom-generator.git",
}

func GenerateSBOM(ctx tcontext.TransferMetadata, repoDir, binaryPath string) ([]byte, error) {
	logger.LogDebug(ctx.Context, "Generating SBOM using Syft", "to_repo_dir", repoDir, "syft_binaryPath", binaryPath)

	// Ensure Syft binary is executable
	if err := os.Chmod(binaryPath, 0o755); err != nil {
		return nil, fmt.Errorf("failed to set executable permission for syft: %w", err)
	}

	// repository directory
	dirFlags := fmt.Sprintf("dir:%s", repoDir)

	// create SBOM in CycloneDX JSON format
	outputFlags := "cyclonedx-json"

	args := []string{"scan", dirFlags, "-o", outputFlags}

	logger.LogDebug(ctx.Context, "Executing SBOM command", "cmd", binaryPath, "args", args)

	// Run Syft
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = repoDir // Ensure it runs from the correct directory

	var outBuffer, errBuffer bytes.Buffer
	cmd.Stdout = &outBuffer
	cmd.Stderr = &errBuffer

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run Syft: %w", err)
	}

	/// store SBOM in memory
	data := outBuffer.Bytes()
	if len(data) == 0 {
		return nil, fmt.Errorf("Syft produced SBOM with empty content")
	}

	logger.LogDebug(ctx.Context, "SBOM generated successfully", "size", len(data))
	return data, nil
}

// CloneRepoWithGit clones a GitHub repository using the Git command-line tool.
func CloneRepoWithGit(ctx tcontext.TransferMetadata, repoURL, branch, targetDir string) error {
	// Ensure Git is installed
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git is not installed, install Git or use --method=api")
	}
	logger.LogDebug(ctx.Context, "🚀 Cloning repository using Git", "repo", repoURL, "directory", targetDir)

	// Run `git clone --depth=1` for faster shallow cloning
	var cmd *exec.Cmd

	if branch == "" {
		// clones the default branch
		logger.LogDebug(ctx.Context, "Repository to be cloned for", "branch", "default")
		cmd = exec.CommandContext(ctx.Context, "git", "clone", "--depth=1", repoURL, targetDir)

	} else {
		logger.LogDebug(ctx.Context, "Repository to be cloned for", "branch", branch)
		// clones the specific branch
		cmd = exec.CommandContext(ctx.Context, "git", "clone", "--depth=1", "--branch", branch, repoURL, targetDir)
	}

	var stderr bytes.Buffer
	cmd.Stdout = io.Discard // Suppress standard output
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}

	logger.LogDebug(ctx.Context, "Repository successfully cloned", "repo", repoURL, "branch", branch)
	return nil
}
