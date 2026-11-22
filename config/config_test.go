// Copyright 2026 Wing Kwan Chu
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"testing"
)

func Test_LoadFile(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		want    Config
		wantErr bool
	}{
		{
			name:    "valid config file",
			file:    "test/config.yaml",
			wantErr: false,
		},
		{
			name:    "null pointer field skips UnmarshalYAML",
			file:    "test/no_config.yaml",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadFile(tt.file)

			if (err != nil) != tt.wantErr {
				t.Fatalf("yaml.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
