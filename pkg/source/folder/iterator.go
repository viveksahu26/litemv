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

package folder

import (
	"fmt"
	"io"

	"github.com/viveksahu26/litemv/pkg/iterator"
	"github.com/viveksahu26/litemv/pkg/tcontext"
)

// FolderIterator iterates over SBOMs found in a folder
type FolderIterator struct {
	sboms []*iterator.SBOM
	index int
}

// NewFolderIterator initializes and returns a new FolderIterator
func NewFolderIterator(sboms []*iterator.SBOM) *FolderIterator {
	return &FolderIterator{
		sboms: sboms,
		index: 0,
	}
}

// Next retrieves the next SBOM in the iteration
func (it *FolderIterator) Next(ctx tcontext.TransferMetadata) (*iterator.SBOM, error) {
	if it.index >= len(it.sboms) {
		return nil, io.EOF
	}

	sbom := it.sboms[it.index]
	it.index++
	return sbom, nil
}

// watchiterator collects sbom on the real time via channel
type WatcherIterator struct {
	sbomChan chan *iterator.SBOM
}

func (it *WatcherIterator) Next(ctx tcontext.TransferMetadata) (*iterator.SBOM, error) {
	select {
	case sbom, ok := <-it.sbomChan:
		if !ok {
			return nil, fmt.Errorf("watcher channel closed")
		}
		return sbom, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
