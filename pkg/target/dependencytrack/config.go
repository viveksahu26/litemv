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

package dependencytrack

type DependencyTrackConfig struct {
	APIURL         string
	APIKey         string
	ProjectName    string
	ProjectVersion string // Added field for project version
	Overwrite      bool
}

func NewDependencyTrackConfig(apiURL, version string, overwite bool) *DependencyTrackConfig {
	return &DependencyTrackConfig{
		APIURL:         apiURL,
		ProjectVersion: version,
		Overwrite:      overwite,
	}
}
