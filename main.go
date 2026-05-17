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

package main

import (
  "fmt"
  "log/slog"
  "net/http"
  "os"
  "sync"

  "github.com/alecthomas/kingpin/v2"

  "github.com/prometheus/client_golang/prometheus"
  versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
  "github.com/prometheus/client_golang/prometheus/promauto"
  "github.com/prometheus/client_golang/prometheus/promhttp"
  "github.com/prometheus/common/promslog"
  "github.com/prometheus/common/promslog/flag"
  "github.com/prometheus/common/version"
  "github.com/prometheus/exporter-toolkit/web"
  "github.com/prometheus/exporter-toolkit/web/kingpinflag"

  "github.com/cwkwan/ssh_exporter/collector"
  "github.com/cwkwan/ssh_exporter/config"
)

const (
  scrapeEndpoint  = "/probe"
  metricsEndpoint = "/metrics"
  namespace       = "ssh"
)

var (
  configFile   = kingpin.Flag("config.file", "Path to configuration file").Default("config.yaml").ExistingFile()
  hostkeyFile  = kingpin.Flag("hostkey.file", "Path to ssh known_hosts file, default to /etc/ssh/ssh_known_hosts").Default("/etc/ssh/ssh_known_hosts").Strings()
  toolkitFlags = kingpinflag.AddFlags(kingpin.CommandLine, ":9342")

  scrapeRequestError = promauto.NewCounter(
    prometheus.CounterOpts{
      Namespace: namespace,
      Name:      "scrape_request_errors_total",
      Help:      "Errors in requests to the exporter",
    },
  )
  scrapeCollectionDuration = promauto.NewHistogramVec(
    prometheus.HistogramOpts{
      Namespace: namespace,
      Name:      "scrape_collection_duration_seconds",
      Help:      "Total time taken from dialing to completed ssh session, before parsing.",
      NativeHistogramBucketFactor: 1.1,

    },
    []string{"module"},
  )
  sc = &SafeConfig{
    C: &config.Config{},
  }

  landingConfig = web.LandingConfig{
    Name:        "SSH Exporter",
    Description: "Prometheus Exporter for SSH targets",
    Version:     version.Info(),
    Links:       []web.LandingLinks{
      {
        Address: scrapeEndpoint,
        Text:    "Scrape endpoint",
      },
      {
        Address: metricsEndpoint,
        Text:    "Metrics endpoint",
      },
    },
  }
)

type SafeConfig struct {
  mu sync.RWMutex
  C  *config.Config
}

func handler(w http.ResponseWriter, r *http.Request, logger *slog.Logger, telemetry collector.Telemetry) {
  query := r.URL.Query()
  target := query.Get("target")
  if len(query["target"]) != 1 || target == "" {
    http.Error(w, "'target' must be specified once", http.StatusBadRequest)
    scrapeRequestError.Inc()
    return
  }
  m := query.Get("module")
  if len(query["module"]) != 1 || m == "" {
    http.Error(w, "'module' must be specified once", http.StatusBadRequest)
    scrapeRequestError.Inc()
    return
  }
  sc.mu.RLock()
  module, ok := sc.C.Modules[m]
  if !ok {
    sc.mu.RUnlock()
    http.Error(w, fmt.Sprintf("Unknown module %s", m), http.StatusBadRequest)
    scrapeRequestError.Inc()
    return
  }
  sc.mu.RUnlock()

  registry := prometheus.NewRegistry()
  c := collector.New(r.Context(), target, m, module, telemetry, logger.With("target", target, "module", m))
  registry.MustRegister(c)

  h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
  h.ServeHTTP(w, r)
}

func (sc *SafeConfig) ReloadConfig(configPath string) (err error) {
  cfg, err := config.LoadFile(configPath)
  if err != nil {
    return err
  }
  sc.mu.Lock()
  sc.C = cfg
  for module := range sc.C.Modules {
    scrapeCollectionDuration.WithLabelValues(module)
  }
  sc.mu.Unlock()
  return nil
}

func main() {
  promslogConfig := &promslog.Config{}
  flag.AddFlags(kingpin.CommandLine, promslogConfig)
  kingpin.Version(version.Print("ssh_exporter"))
  kingpin.HelpFlag.Short('h')
  kingpin.Parse()

  logger := promslog.New(promslogConfig)

  logger.Info("Starting ssh_exporter", "version", version.Info())
  logger.Info("operational information", "build_context", version.BuildContext())

  prometheus.MustRegister(versioncollector.NewCollector("ssh_exporter"))
  if err := sc.ReloadConfig(*configFile); err != nil {
    logger.Error("Error loading config", "err", err)
    os.Exit(1)
  }

  telemetry := collector.Telemetry{
    ScrapeCollectionDuration: scrapeCollectionDuration,
    ScrapeRequestError: scrapeRequestError,
    ScrapeDuration: promauto.NewHistogramVec(
      prometheus.HistogramOpts{
        Namespace: namespace,
        Name:      "scrape_duration_seconds",
        Help:      "Total time taken from dialing to completed parsing.",
        NativeHistogramBucketFactor: 1.1,
      },
      []string{"module"},
    ),
    ScrapeCount: promauto.NewCounter(
      prometheus.CounterOpts{
        Namespace: namespace,
        Name:      "scrape_count_total",
        Help:      "Number of scrape sent.",
      },
    ),
    ScrapeInflight: promauto.NewGauge(
      prometheus.GaugeOpts{
        Namespace: namespace,
        Name:      "scrape_in_flight",
        Help:      "Current number of scrapes being requested.",
      },
    ),
  }

  landingPage, err := web.NewLandingPage(landingConfig)
  if err != nil {
    logger.Error("Error creating landing page", "err", err)
    os.Exit(1)
  }
  http.Handle("/", landingPage)
  http.Handle(metricsEndpoint, promhttp.Handler())
  http.HandleFunc(scrapeEndpoint, func(w http.ResponseWriter, r *http.Request) {
    handler(w, r, logger, telemetry)
  })

  server := &http.Server{}
  if err := web.ListenAndServe(server, toolkitFlags, logger); err != nil {
    logger.Error("Error starting HTTP server", "err", err)
    os.Exit(1)
  }
}
