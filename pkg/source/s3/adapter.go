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

package s3

import (
	"fmt"
	"strings"

	"github.com/viveksahu26/litemv/pkg/iterator"
	"github.com/viveksahu26/litemv/pkg/logger"
	"github.com/viveksahu26/litemv/pkg/tcontext"
	"github.com/viveksahu26/litemv/pkg/types"
	"github.com/viveksahu26/litemv/pkg/utils"
	"github.com/spf13/cobra"
)

type S3Adapter struct {
	Config         *S3Config
	Role           types.AdapterRole // "input" or "output" adapter type
	ProcessingMode types.ProcessingMode
	Fetcher        SBOMFetcher
}

// AddCommandParams adds S3-specific CLI flags
func (s3 *S3Adapter) AddCommandParams(cmd *cobra.Command) {
	cmd.Flags().String("in-s3-bucket-name", "", "S3 bucket name")
	cmd.Flags().String("in-s3-region", "", "S3 region")
	cmd.Flags().String("in-s3-prefix", "", "S3 prefix")
	cmd.Flags().String("in-s3-access-key", "", "AWS access key for S3")
	cmd.Flags().String("in-s3-secret-key", "", "AWS secret key for S3")
}

// ParseAndValidateParams validates the S3 adapter params
func (s *S3Adapter) ParseAndValidateParams(cmd *cobra.Command) error {
	var (
		bucketNameFlag, regionFlag, prefixFlag, accessKeyFlag, secretKeyFlag string
		missingFlags                                                         []string
		invalidFlags                                                         []string
	)

	bucketNameFlag = "in-s3-bucket-name"
	regionFlag = "in-s3-region"
	prefixFlag = "in-s3-prefix"
	accessKeyFlag = "in-s3-access-key"
	secretKeyFlag = "in-s3-secret-key"

	var bucketName, region, prefix string
	var fetcher SBOMFetcher

	if s.ProcessingMode == types.FetchSequential {
		fetcher = &S3SequentialFetcher{}
	} else if s.ProcessingMode == types.FetchParallel {
		fetcher = &S3ParallelFetcher{}
	} else {
		return fmt.Errorf("unsupported processing mode: %s", s.ProcessingMode)
	}

	// validate flags for S3 adapter, all flags should start with "in-s3-"
	err := utils.FlagValidation(cmd, types.S3AdapterType, types.InputAdapterFlagPrefix)
	if err != nil {
		return fmt.Errorf("s3 flag validation failed: %w", err)
	}

	// extract the bucket name
	bucketName, _ = cmd.Flags().GetString(bucketNameFlag)
	if bucketName == "" {
		missingFlags = append(missingFlags, bucketNameFlag)
	}

	// extrack the region name
	region, _ = cmd.Flags().GetString(regionFlag)
	if region == "" {
		// set default as us-east-1
		region = "us-east-1"
	}

	// extract the prefix name
	// if prefix is empty that means all prefix inside a bucket
	prefix, _ = cmd.Flags().GetString(prefixFlag)

	// extract AWS access Key
	accessKey, _ := cmd.Flags().GetString(accessKeyFlag)

	// extract AWS secret Key
	secretKey, _ := cmd.Flags().GetString(secretKeyFlag)

	if len(missingFlags) > 0 {
		return fmt.Errorf("missing flags: %s", strings.Join(missingFlags, ", "))
	}

	if len(invalidFlags) > 0 {
		return fmt.Errorf("invalid input adapter flag usage:\n %s\n\nUse 'sbommv transfer --help' for correct usage.", strings.Join(invalidFlags, "\n "))
	}

	cfg := NewS3Config()
	cfg.SetProcessingMode(s.ProcessingMode)
	cfg.SetBucketName(bucketName)
	cfg.SetRegion(region)
	cfg.SetPrefix(prefix)
	cfg.SetAccessKey(accessKey)
	cfg.SetSecretKey(secretKey)

	s.Config = cfg
	s.Fetcher = fetcher

	return nil
}

func (s3 *S3Adapter) FetchSBOMs(ctx tcontext.TransferMetadata) (iterator.SBOMIterator, error) {
	logger.LogDebug(ctx.Context, "Initializing SBOM fetching", "mode", s3.ProcessingMode)
	return s3.Fetcher.Fetch(ctx, s3.Config)
}

func (s3 *S3Adapter) UploadSBOMs(ctx tcontext.TransferMetadata, iterator iterator.SBOMIterator) error {
	return fmt.Errorf("S3 adapter does not support SBOM uploading when it is in input adapter role")
}

func (s3 *S3Adapter) DryRun(ctx tcontext.TransferMetadata, iterator iterator.SBOMIterator) error {
	reporter := NewS3Reporter(false, "", s3.Config.BucketName, s3.Config.Prefix)
	return reporter.DryRun(ctx, iterator)
}
