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

package collector

import (
	"math"
	"os"
	"testing"

	"github.com/cwkwan/ssh_exporter/config"
)

func TestExpand(t *testing.T) {
	v := "testvar"
	os.Setenv("TESTVAR", v)
	os.Setenv("TESTVAR2", "z22")

	param := map[string]string{
		"var": "secret_param",
	}
	module := config.Module{
		Password: "${TESTVAR} -@{Not_exist_var}- @{var} \\@{} \\@{escape} \\${escape}${TESTVAR2}",
	}

	module.Password = expand(module.Password, func(s string) string {
		if s[0] == '$' {
			return os.Getenv(s[1:])
		}
		if s[0] == '@' {
			return param[s[1:]]
		}
		return ""
	})

	if module.Password != "testvar -- secret_param \\@{} @{escape} ${escape}z22" {
		t.Errorf(`expand(module.Password) = %v, want "testvar -- secret_param \@{} @{escape} ${escape}z22"`, module.Password)
	}
}

func Test_parseNaN(t *testing.T) {
	rs := map[string]string{
		"c": "string",
		"d": "",
	}

	tests := []struct {
		exp     string
		wantErr bool
	}{
		{"c", true},
		{"d", true},
		{"e", true},
	}

	for _, test := range tests {
		got, err := parse(rs, test.exp)

		if (err != nil) != test.wantErr {
			t.Errorf("parse() error = %v, wantErr %v", err, test.wantErr)
		}
		if !math.IsNaN(got) {
			t.Errorf("Expecting toFloat() to return NaN")
		}
	}
}

func Test_parse(t *testing.T) {
	rs := map[string]string{
		"a": "123",
		"b": "456",
	}

	tests := []struct {
		exp     string
		want    float64
		wantErr bool
	}{
		{"a + b", 123456, false},
		{"float(a) + float(b)", 579, false},
		{"7", 7, false},
	}

	for _, test := range tests {
		got, err := parse(rs, test.exp)

		if (err != nil) != test.wantErr {
			t.Errorf("parse() error = %v, wantErr %v", err, test.wantErr)
		}
		if got != test.want {
			t.Errorf("parse() want = %v, got %v", test.want, got)
		}
	}
}

func Test_toFloat(t *testing.T) {
	tests := []struct {
		s       string
		want    float64
		wantErr bool
	}{
		{"1.1", 1.1, false},
		{"true", 1.0, false},
		{"F", 0.0, false},
	}

	for _, test := range tests {
		got, err := toFloat(test.s)

		if (err != nil) != test.wantErr {
			t.Errorf("toFloat() error = %v, wantErr %v", err, test.wantErr)
		}
		if got != test.want {
			t.Errorf("toFloat() want = %v, got %v", test.want, got)
		}
	}
}

func Test_toFloatNaN(t *testing.T) {
	got, err := toFloat("")

	if err == nil {
		t.Errorf("toFloat() should return error when NaN")
	}
	if !math.IsNaN(got) {
		t.Errorf("Expecting toFloat() to return NaN")
	}
}
