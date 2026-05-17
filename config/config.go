package config

import (
  "os"

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

func (c *Metric) UnmarshalYAML(unmarshal func(any) error) error {
  *c = DefaultHistogramOpts
  type alias Metric
  return unmarshal((*alias)(c))
}

type GrokPattern struct {
  *grok.Grok
}

func (gp *GrokPattern) UnmarshalYAML(b []byte) error {
  var m map[string]string

  if err := yaml.Unmarshal(b, &m); err != nil {
    return err
  }
  g := grok.New()
  g.AddPatterns(m)

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
    return nil, err
  }

  return cfg, nil
}
