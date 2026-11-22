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
	"context"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/cwkwan/ssh_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	ignoreHostKey = kingpin.Flag("ignore-host-key", "Accept any host key, insecure. hostkey.file and known_hosts_file will be ignored").Default("false").Bool()
)

type Telemetry struct {
	ScrapeCollectDuration *prometheus.HistogramVec
	ScrapeDuration        *prometheus.HistogramVec
	ScrapeCount           prometheus.Counter
	ScrapeRequestError    prometheus.Counter
	ScrapeInflight        prometheus.Gauge
}

type Collector struct {
	name      string // module name
	ctx       context.Context
	target    string
	telemetry *Telemetry
	module    *config.Module
	logger    *slog.Logger
	results   []result
	jobs      []job
}

type constMetric struct {
	desc      *prometheus.Desc
	fqname    string
	valueType prometheus.ValueType
	value     string
}

type histogram struct {
	opts       prometheus.HistogramOpts
	value      string
	labelnames []string
}

type job struct {
	cmds       []string
	maskedCmds []string
}

type result struct {
	data    []byte
	metrics []metric
}

type metric struct {
	name                string
	grok                string
	continueOnDuplicate bool
	labelvalues         []string
	constMetrics        []constMetric
	histograms          []histogram
}

func (c Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, result := range c.results {
		for _, metric := range result.metrics {
			for _, constMetric := range metric.constMetrics {
				ch <- constMetric.desc
			}
		}
	}
}

func (c Collector) Collect(ch chan<- prometheus.Metric) {
	logger := c.logger.With("module", c.name)
	scrapeCollectDurationDesc := prometheus.NewDesc(
		"scrape_collect_duration_seconds",
		"scrape_duration_seconds minus the time taken to parse the command outputs.",
		nil, nil)
	scrapeDurationDesc := prometheus.NewDesc(
		"scrape_duration_seconds",
		"Total time taken from dialing, to running commands, to closed ssh session, to complete parsing.",
		nil, nil)
	start := time.Now()
	c.telemetry.ScrapeInflight.Inc()
	c.telemetry.ScrapeCount.Inc()
	results, err := run(c, logger)
	if err != nil {
		logger.Warn("Error when scraping", "module", c.name, "module.Eof", c.module.Eof, "target", c.target, "err", err)
	}
	duration := time.Since(start).Seconds()
	c.telemetry.ScrapeInflight.Dec()
	c.telemetry.ScrapeCollectDuration.WithLabelValues(c.name).Observe(duration)
	scrapeCollectDuration := prometheus.MustNewConstMetric(
		scrapeCollectDurationDesc,
		prometheus.GaugeValue,
		duration,
	)
	ch <- scrapeCollectDuration

	// results can be nil/partial with errors
	g := c.module.GrokPatterns
	for _, result := range results {
		for _, metric := range result.metrics {
			err := g.Compile(metric.grok, false)
			if err != nil {
				logger.Error("Error compile Grok query", "grok", metric.grok, "err", err)
				return
			}

			matches, err := g.ParseString(string(result.data))
			if err != nil {
				logger.Error("Error parsing result.data with Grok query", "grok", metric.grok, "err", err)
				return
			}

			for _, constMetric := range metric.constMetrics {
				collected := make(map[uint64]bool)
				for _, match := range matches {
					labelvalues := parseLabel(match, metric.labelvalues)
					key := hashStringSlice(labelvalues)
					value, err := parse(match, constMetric.value) // true,false will be parsed as boolean
					if err != nil {                               // so they won't work as grok field
						logger.Error("Error parsing metric value", "value", constMetric.value, "err", err)
					}
					m := prometheus.MustNewConstMetric(
						constMetric.desc,
						constMetric.valueType,
						value,
						labelvalues...,
					)
					if collected[key] {
						logger.Warn("Multiple results returned for metric with the exact same name and label values", "metric fqname", constMetric.fqname, "label values", labelvalues)
						if !metric.continueOnDuplicate {
							break
						}
					} else {
						collected[key] = true
						ch <- m
					}
				}
			}
			// Need to loop matches separately for histogram
			// can't tell if it will become a vector until next line is parsed
			for _, histogram := range metric.histograms {
				m := prometheus.NewHistogramVec(histogram.opts, histogram.labelnames)
				for _, match := range matches {
					labelvalues := parseLabel(match, metric.labelvalues)
					value, err := parse(match, histogram.value) // true,false will be parsed as boolean
					if err != nil {                             // so they won't work as grok field
						logger.Error("Error parsing metric value", "value", histogram.value, "err", err)
					}
					m.WithLabelValues(labelvalues...).Observe(value)
				}
				m.Collect(ch)
			}
		}
	}
	duration = time.Since(start).Seconds()
	c.telemetry.ScrapeDuration.WithLabelValues(c.name).Observe(duration)
	scrapeDuration := prometheus.MustNewConstMetric(
		scrapeDurationDesc,
		prometheus.GaugeValue,
		duration,
	)
	ch <- scrapeDuration
}

func run(c Collector, logger *slog.Logger) ([]result, error) {
	algorithms := ssh.SupportedAlgorithms()
	auth, _ := authMethod(c.module, logger)
	config := &ssh.ClientConfig{
		Config: ssh.Config{
			KeyExchanges: algorithms.KeyExchanges,
			Ciphers:      algorithms.Ciphers,
			MACs:         algorithms.MACs,
		},
		User:            c.module.User,
		Auth:            auth,
		Timeout:         time.Duration(c.module.Timeout) * time.Millisecond,
		HostKeyCallback: hostKeyCallback(c.module, logger),
		// Should check if hostKey algorithm is included in
		// algorithms.HostKeys.
		HostKeyAlgorithms: algorithms.HostKeys,
	}
	var data [][]byte
	var err error

	sshClient := newSSHClient(c.target, config, c.telemetry)
	defer sshClient.close()

	re, err := regexp.Compile(c.module.Eof)
	if err != nil {
		re, _ = regexp.Compile("")
	}

	if c.module.StartShell {
		if re.String() == "" {
			data, err = sshClient.runShellWaitTimeOut(c.module.CmdTimeout, c.jobs, logger)
		} else {
			data, err = sshClient.runShellWaitEof(c.module.CmdTimeout, re, c.jobs, logger)
		}
	} else {
		data, err = sshClient.runBulk(c.module.CmdTimeout, c.jobs, logger)
	}
	if err != nil {
		logger.Warn("Non nil error from interactive shell", "target", c.target, "module", c.name, "err", err)
	}
	for i := range data {
		c.results[i].data = data[i]
	}

	return c.results, err
}

func authMethod(m *config.Module, logger *slog.Logger) ([]ssh.AuthMethod, error) {
	var auth []ssh.AuthMethod

	if m.Password != "" {
		auth = append(auth, ssh.Password(m.Password))
	}
	if m.PrivateKey != "" {
		key, err := os.ReadFile(m.PrivateKey)
		if err != nil {
			logger.Error("Failed to read private key", "err", err, "private_key file", m.PrivateKey)
			return nil, err
		}
		var signer ssh.Signer
		if m.PrivateKeyPass != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(m.PrivateKeyPass))
			if err != nil {
				logger.Error("Failed to parse private key with passphrase", "key", m.PrivateKey, "err", err)
				return nil, err
			}
		} else {
			signer, err = ssh.ParsePrivateKey(key)
			if err != nil {
				logger.Error("Failed to parse private key", "key", m.PrivateKey, "err", err)
				return nil, err
			}
		}
		if m.Certificate != "" {
			certificate, err := os.ReadFile(m.Certificate)
			if err != nil {
				logger.Error("Failed to read certificate", "certificate", m.Certificate, "err", err)
				return nil, err
			}
			pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certificate)
			if err != nil {
				logger.Error("Failed to parse certificate", "certificate", m.Certificate, "err", err)
				return nil, err
			}
			cert, ok := pubKey.(*ssh.Certificate)
			if !ok {
				logger.Error("Certificate is not an SSH certificate", "certificate", m.Certificate)
				return nil, err
			}
			signer, err = ssh.NewCertSigner(cert, signer)
			if err != nil {
				logger.Error("Failed to create certificate signer", "certificate", m.Certificate, "key", m.PrivateKey)
				return nil, err
			}
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}

	if len(auth) == 0 {
		err := errors.New("No authentication specified")
		logger.Error("either password or private_key need to be provided", "err", err)
		return nil, err
	}

	return auth, nil
}

func hostKeyCallback(m *config.Module, logger *slog.Logger) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		var cb ssh.HostKeyCallback
		var err error
		if *ignoreHostKey {
			cb = ssh.InsecureIgnoreHostKey()
		} else {
			cb, err = knownhosts.New(m.KnownHostsFile)
			if err != nil {
				logger.Error("Error creating HostKeyCallback function", "err", err, "known_hosts file", m.KnownHostsFile)
				return err
			}
		}
		return cb(hostname, remote, key)
	}
}

func New(ctx context.Context, param url.Values, target string, name string, module *config.Module, telemetry *Telemetry, logger *slog.Logger) *Collector {

	var results []result
	var jobs []job

	keys := []*string{&module.Password, &module.PrivateKey, &module.PrivateKeyPass, &module.Certificate, &module.Eof}

	for _, key := range keys {
		*key = expand(*key, func(s string) string {
			if s[0] == '$' {
				return os.Getenv(s[1:])
			}
			if s[0] == '@' {
				return param.Get(s[1:])
			}
			return ""
		})
	}

	for _, j := range module.Jobs {
		metrics := make([]metric, len(j.Metrics))
		n := 0
		for parentname, m := range j.Metrics {
			labelnames := make([]string, len(m.Labels))
			labelvalues := make([]string, len(m.Labels))
			i := 0
			for k, v := range m.Labels {
				labelnames[i] = k
				labelvalues[i] = v
				i++
			}

			gauges := make([]constMetric, len(m.Gauges))
			i = 0
			for name, value := range m.Gauges {
				fqname := strings.Join([]string{parentname, name}, "_")
				g := constMetric{
					desc:      prometheus.NewDesc(fqname, m.Help, labelnames, nil),
					fqname:    fqname,
					valueType: prometheus.GaugeValue,
					value:     value,
				}
				gauges[i] = g
				i++
			}
			counters := make([]constMetric, len(m.Counters))
			i = 0
			for name, value := range m.Counters {
				fqname := strings.Join([]string{parentname, name}, "_")
				m := constMetric{
					desc:      prometheus.NewDesc(fqname, m.Help, labelnames, nil),
					fqname:    fqname,
					valueType: prometheus.CounterValue,
					value:     value,
				}
				counters[i] = m
				i++
			}
			constMetrics := append(gauges, counters...)

			histograms := make([]histogram, len(m.Histograms))
			i = 0
			for name, value := range m.Histograms {
				fqname := strings.Join([]string{parentname, name}, "_")
				h := histogram{
					opts: prometheus.HistogramOpts{
						Name:                           fqname,
						Help:                           m.Help,
						NativeHistogramBucketFactor:    m.BucketFactor,
						NativeHistogramMaxBucketNumber: m.BucketNumber,
					},
					value:      value,
					labelnames: labelnames,
				}
				histograms[i] = h
				i++
			}

			metric := metric{
				name:                parentname,
				grok:                m.GrokCompile,
				continueOnDuplicate: m.ContineOnDuplicate,
				labelvalues:         labelvalues,
				constMetrics:        constMetrics,
				histograms:          histograms,
			}
			metrics[n] = metric
			n++
		}
		result := result{
			metrics: metrics,
		}

		cmds := make([]string, len(j.Commands))
		for i, cmd := range j.Commands {
			cmd = expand(cmd, func(s string) string {
				if s[0] == '$' {
					return os.Getenv(s[1:])
				}
				if s[0] == '@' {
					return param.Get(s[1:])
				}
				return ""
			})
			cmds[i] = cmd
		}

		newJob := job{
			cmds:       cmds,
			maskedCmds: j.Commands,
		}
		jobs = append(jobs, newJob)
		results = append(results, result)
	}

	return &Collector{
		name:      name,
		ctx:       ctx,
		target:    target,
		module:    module,
		telemetry: telemetry,
		logger:    logger,
		results:   results,
		jobs:      jobs,
	}
}
