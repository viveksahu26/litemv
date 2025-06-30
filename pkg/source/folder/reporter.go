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
// -------------------------------------------------------------------------

package folder

import (
	"fmt"
	"io"

	"github.com/viveksahu26/litemv/pkg/iterator"
	"github.com/viveksahu26/litemv/pkg/logger"
	"github.com/viveksahu26/litemv/pkg/sbom"
	"github.com/viveksahu26/litemv/pkg/tcontext"
)

type FolderReporter struct {
	verbose    bool
	inputDir   string
	folderPath string
}

func NewFolderReporter(verbose bool, inputDir, folderPath string) *FolderReporter {
	return &FolderReporter{
		verbose:    verbose,
		inputDir:   inputDir,
		folderPath: folderPath,
	}
}

func (r *FolderReporter) DryRun(ctx tcontext.TransferMetadata, iter iterator.SBOMIterator) error {
	logger.LogDebug(ctx.Context, "Dry-run mode: Displaying SBOMs fetched from folder")
	processor := sbom.NewSBOMProcessor(r.inputDir, r.verbose)
	sbomCount := 0
	fmt.Println("\n📦 Details of all Fetched SBOMs by Folder Input Adapter")

	for {
		sbom, err := iter.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.LogError(ctx.Context, err, "Error retrieving SBOM from iterator")
			return err
		}
		processor.Update(sbom.Data, "", sbom.Path)
		doc, err := processor.ProcessSBOMs()
		if err != nil {
			logger.LogError(ctx.Context, err, "Failed to process SBOM")
			return err
		}
		if r.inputDir != "" {
			if err := processor.WriteSBOM(doc, ""); err != nil {
				logger.LogError(ctx.Context, err, "Failed to write SBOM")
				return err
			}
		}
		if r.verbose {
			fmt.Printf("\n-------------------- 📜 SBOM Content --------------------\n")
			fmt.Printf("📂 Filename: %s\n", doc.Filename)
			fmt.Printf("📦 Format: %s | SpecVersion: %s\n\n", doc.Format, doc.SpecVersion)
			fmt.Println(string(doc.Content))
			fmt.Println("------------------------------------------------------")
		}
		sbomCount++
		fmt.Printf(" - 📁 Folder: %s | Format: %s | SpecVersion: %s | Filename: %s\n",
			r.folderPath, doc.Format, doc.SpecVersion, doc.Filename)
	}
	fmt.Printf("📊 Total SBOMs: %d\n", sbomCount)
	return nil
}
