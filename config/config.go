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
  "os"
  "fmt"
  "errors"

  "github.com/goccy/go-yaml"
  "github.com/cwkwan/go-grok"
)

var (
  DefaultHistogramOpts = Metric{
    BucketNumber: 8,
    BucketFactor: 1.1,
  }
)

type Config struct {
  Modules map[string]*Module `yaml:"modules"`
}

type Module struct {
  User              string        `yaml:"user"`
  Password          string        `yaml:"password"`
  PrivateKey        string        `yaml:"private_key"`
  Certificate       string        `yaml:"certificate"`
  KnownHostsFile    string        `yaml:"known_hosts_file"`
  HostKeyAlgorithms []string      `yaml:"host_key_algorithms"`
  Timeout           int           `yaml:"timeout"`
  GrokPatterns      GrokPattern   `yaml:"grok_pattern"`
  Jobs              []Job         `yaml:"jobs"`
}

type Job struct {
  Metrics     map[string]Metric  `yaml:"metrics"`
  Command     string             `yaml:"command"`
}

type Metric struct {
  Help            string             `yaml:"help"`
  GrokCompile     string             `yaml:"grok_compile"`
  BucketNumber    uint32             `yaml:"bucket_number"`
  BucketFactor    float64            `yaml:"bucket_factor"`
  Labels          map[string]string  `yaml:"labels"`
  Gauges          map[string]string  `yaml:"gauge"`
  Counters        map[string]string  `yaml:"counter"`
  Histograms      map[string]string  `yaml:"histogram"`
}

type GrokPattern struct {
  *grok.Grok
}

func (c *Metric) UnmarshalYAML(unmarshal func(any) error) error {
  *c = DefaultHistogramOpts
  type alias Metric
  return unmarshal((*alias)(c))
}

func (gp *GrokPattern) UnmarshalYAML(b []byte) error {
  var m map[string]string

  if err := yaml.Unmarshal(b, &m); err != nil {
    return err
  }
  g := grok.New()
  if err := g.AddPatterns(m); err != nil {
    return fmt.Errorf("Grok pattern: %w", err)
  }

  gp.Grok = g
  return nil
}

func LoadFile(configPath string) (*Config, error) {
  cfg := &Config{}

  config, err := os.ReadFile(configPath)
  if err != nil {
    return nil, err
  }

  if err := yaml.Unmarshal(config, cfg); err != nil {
    return nil, errors.New(yaml.FormatError(err, false, false))
  }

  return cfg, nil
}
