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

func TestParse(t *testing.T) {
	s := map[string]string{
		"s1": "123",
		"s2": "456",
		"c":  "string",
		"d":  "",
	}

	exp := "s1 + s2"
	v, err := parse(s, exp)
	if err != nil {
		t.Errorf(`Error returned from parse(%v, %v). Expect none, err returned: %v`, s, exp, err)
	}
	if v != 123456 {
		t.Errorf(`v = %v, expect 123456`, v)
	}

	exp = "float(s1) + float(s2)"
	v, err = parse(s, exp)
	if err != nil {
		t.Errorf(`Error returned from parse(%v, %v). Expect none, err returned: %v`, s, exp, err)
	}
	if v != 579 {
		t.Errorf(`v = %v, expect 579`, v)
	}

	exp = "float(c)"
	v, err = parse(s, exp)
	if !math.IsNaN(v) {
		t.Errorf(`v = %v, expect math.NaN`, v)
	}

	exp = "d"
	v, err = parse(s, exp)
	if !math.IsNaN(v) {
		t.Errorf(`v = %v, expect math.NaN`, v)
	}

	exp = "5"
	v, err = parse(s, exp)
	if v != 5 {
		t.Errorf(`v = %v, expect 5`, v)
	}
}

func TestToFloat(t *testing.T) {
	s := "1.0"
	v, err := toFloat(s)
	if err != nil {
		t.Errorf(`Error returned from toFloat("%v"). Expect none, err returned: %v`, s, err)
	}
	if v != 1.0 {
		t.Errorf(`toFloat("%v"), want %v`, s, v)
	}

	s = "true"
	v, err = toFloat(s)
	if err != nil {
		t.Errorf(`Error returned from toFloat("%v"). Expect none, err returned: %v`, s, err)
	}
	if v != 1.0 {
		t.Errorf(`toFloat("%v"), want %v`, s, v)
	}

	s = "false"
	v, err = toFloat(s)
	if err != nil {
		t.Errorf(`Error returned from toFloat("%v"). Expect none, err returned: %v`, s, err)
	}
	if v != 0.0 {
		t.Errorf(`toFloat("%v"), want %v`, s, v)
	}

	s = ""
	v, err = toFloat(s)
	if err == nil {
		t.Errorf(`No Error returned from toFloat("%v"). Expecting error, getting none`, s)
	}
	if !math.IsNaN(v) {
		t.Errorf(`toFloat("%v") = %v, expect math.NaN`, s, v)
	}

}
