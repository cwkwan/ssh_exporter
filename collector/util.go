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
	"fmt"
	"hash/fnv"
	"math"
	"strconv"

	"github.com/expr-lang/expr"
)

// Expand replaces ${var} or $var in the string based on the mapping function.
// For example, [os.ExpandEnv](s) is equivalent to [os.Expand](s, [os.Getenv]).
func expand(s string, mapping func(string) string) string {
	var buf []byte
	// assume only ASCII in ${}
	i := 0
	for j := 0; j < len(s); j++ {
		if (s[j] == '$' || s[j] == '@') && j+1 < len(s) {
			if buf == nil {
				buf = make([]byte, 0, 2*len(s))
			}
			buf = append(buf, s[i:j]...)
			name, w := getVarName(s[j+1:])
			if name == "" {
				buf = append(buf, s[j:j+w+1]...)
			} else {
				if j > 0 && s[j-1] == '\\' {
					buf = append(buf[:len(buf)-1], s[j:j+w+1]...)
				} else {
					buf = append(buf, mapping(string(s[j])+name)...)
				}
			}
			j += w
			i = j + 1
		}
	}
	if buf == nil {
		return s
	}
	return string(buf) + s[i:]
}

func getVarName(s string) (string, int) {
	if s[0] == '{' {
		for i := 1; i < len(s); i++ {
			if isBeacon(s[i]) {
				return "", i
			}
			if s[i] == '}' {
				if i == 1 {
					return "", 2
				}
				return s[1:i], i + 1
			}
		}
		return "", 1
	}
	return "", 0
}

func isBeacon(c uint8) bool {
	return c == '$' || c == '@' || c == '\\' || c == '{' || c == '/' || c == '?'
}

func hashStringSlice(slice []string) uint64 {
	h := fnv.New64a()
	for _, str := range slice {
		h.Write([]byte(str))
		h.Write([]byte{0}) // Null byte separator ensures structure boundaries are preserved
	}
	return h.Sum64()
}

func compile(rs map[string]string, value string) string {
	program, err := expr.Compile(value, expr.Env(rs))
	if err != nil {
		return value
	}
	v, err := expr.Run(program, rs)
	if err != nil {
		return value
	}

	return fmt.Sprint(v)
}

func parse(rs map[string]string, value string) (float64, error) {
	v, err := toFloat(value)
	if err != nil {
		v, err = toFloat(compile(rs, value))
		if err != nil {
			return v, err
		}
	}
	return v, nil
}

func parseLabel(rs map[string]string, labels []string) []string {
	values := make([]string, len(labels))
	for i, label := range labels {
		value := compile(rs, label)
		values[i] = value
	}
	return values
}

func toFloat(s string) (float64, error) {
	var err error
	var v float64
	if v, err = strconv.ParseFloat(s, 64); err == nil {
		return v, nil
	}

	if ok, err := strconv.ParseBool(s); err == nil {
		if ok {
			return 1.0, nil
		}
		return 0.0, nil
	}

	return math.NaN(), err
}
