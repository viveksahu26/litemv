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

package converter

import (
	"bytes"
	"fmt"
	"time"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	"github.com/sirupsen/logrus"
	"github.com/viveksahu26/litemv/pkg/logger"
	sbomd "github.com/viveksahu26/litemv/pkg/sbom"
	"github.com/viveksahu26/litemv/pkg/tcontext"
)

// bufferWriteCloser wraps *bytes.Buffer to implement io.WriteCloser
type bufferWriteCloser struct {
	*bytes.Buffer
}

func (b *bufferWriteCloser) Close() error {
	return nil // No-op for in-memory buffer
}

// ConvertSBOM converts SBOM from SPDX to CDX format using protobom
func ConvertSBOM(ctx tcontext.TransferMetadata, sbomData []byte, targetFormat sbomd.FormatSpec) ([]byte, error) {
	logger.LogDebug(ctx.Context, "Iniatializing for SBOM conversion from SPDX to CDX")

	originalLevel := logrus.GetLevel()   // Mute protobom warnings of data lost
	logrus.SetLevel(logrus.ErrorLevel)   // Only ERROR and above from protobom
	defer logrus.SetLevel(originalLevel) // Restore after

	spec, version, err := sbomd.DetectSBOMSpecAndVersion(sbomData)
	if err != nil {
		return nil, fmt.Errorf("ConvertSBOM: %w", err)
	}

	if spec == targetFormat {
		logger.LogDebug(ctx.Context, "No conversion needed", "format", spec, "spec_version", version)
		return sbomData, nil
	}

	if spec != sbomd.FormatSpecSPDX {
		return nil, fmt.Errorf("conversion layer is provided with SBOM other than SPDX, therefore no conversion will take place")
	}

	logger.LogDebug(ctx.Context, "Detected SPDX SBOM", "version", version)

	var spdx23SbomData []byte
	var doc *sbom.Document

	switch sbomd.FormatSpecVersion(version) {

	case sbomd.FormatSpecVersionSPDXV2_1:
		return nil, fmt.Errorf("unsupported conversion from SPDX 2.1 to %s", targetFormat)

	case sbomd.FormatSpecVersionSPDXV2_2:
		spdx23SbomData, err = ConvertSPDX22ToSPDX23(ctx, sbomData)
		if err != nil {
			return nil, fmt.Errorf("converting SPDX 2.2 to 2.3: %w", err)
		}

	case sbomd.FormatSpecVersionSPDXV2_3:
		spdx23SbomData = sbomData

	default:
		return nil, fmt.Errorf("unsupported SPDX version: %s", version)
	}

	// Parse the converted 2.3 SBOM with Protobom
	doc, err = parseSBOM(spdx23SbomData)
	if err != nil {
		return nil, fmt.Errorf("Conversion: %w", err)
	}

	logger.LogDebug(ctx.Context, "Converting SBOM", "source", spec, "source version", version, "target", targetFormat)

	// Serialize to CycloneDX format from SPDX:2.3
	if targetFormat == sbomd.FormatSpecCycloneDX {
		// enrichedDoc := enrichCycloneDXSBOM(doc)
		return serializeToCycloneDX(ctx, doc)
	}

	return nil, fmt.Errorf("unsupported conversion to %s", targetFormat)
}

// parseSBOM parse the SBOM using Protobom
func parseSBOM(sbomData []byte) (*sbom.Document, error) {
	r := reader.New()

	// parse a sbom document from a sbom data using protobom
	doc, err := r.ParseStream(bytes.NewReader(sbomData))
	if err != nil {
		return nil, fmt.Errorf("Conversion: %w", err)
	}
	return doc, nil
}

func serializeToCycloneDX(ctx tcontext.TransferMetadata, doc *sbom.Document) ([]byte, error) {
	logger.LogDebug(ctx.Context, "Initializing protobom serialization of SBOM from SPDX to CycloneDX")
	w := writer.New()
	buf := &bytes.Buffer{}

	// channel to receive result or error
	resultChan := make(chan struct {
		data []byte
		err  error
	}, 1)

	go func(buffer *bytes.Buffer) {
		logger.LogDebug(ctx.Context, "Starting WriteStreamWithOptions", "nodeCount", len(doc.NodeList.Nodes))
		err := w.WriteStreamWithOptions(doc, buffer, &writer.Options{Format: formats.CDX15JSON})
		data := buffer.Bytes()
		resultChan <- struct {
			data []byte
			err  error
		}{data, err}
	}(buf)

	// wait for result with timeout
	select {
	case res := <-resultChan:
		if res.err != nil {
			return nil, fmt.Errorf("Conversion: %w", res.err)
		}
		logger.LogDebug(ctx.Context, "Finished WriteStreamWithOptions")
		data := res.data
		if len(data) == 0 {
			return nil, fmt.Errorf("empty protobom serialized CycloneDX SBOM")
		}
		logger.LogDebug(ctx.Context, "Successfully protobom serialization of SBOM from SPDX to CycloneDX")
		return data, nil
	case <-time.After(30 * time.Second): // 30 seconds timeout
		return nil, fmt.Errorf("Conversion: serialization timed out after 30 seconds")
	}
}
