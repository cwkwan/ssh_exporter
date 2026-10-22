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
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
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
	results   []Result
}

type Result struct {
	job     []string
	data    []byte
	metrics []Metric
}

type Metric struct {
	name                string
	grok                string
	continueOnDuplicate bool
	labelvalues         []string
	constMetrics        []ConstMetric
	histograms          []Histogram
}

type ConstMetric struct {
	desc      *prometheus.Desc
	fqname    string
	valueType prometheus.ValueType
	value     string
}

type Histogram struct {
	opts       prometheus.HistogramOpts
	value      string
	labelnames []string
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
		return
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
			logger.Debug("resultset", "data", result.data, "matches", matches, "grok", metric.grok, "err", err)

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
	logger.Debug("Finished parsing", "duration_seconds", duration)
	c.telemetry.ScrapeDuration.WithLabelValues(c.name).Observe(duration)
	scrapeDuration := prometheus.MustNewConstMetric(
		scrapeDurationDesc,
		prometheus.GaugeValue,
		duration,
	)
	ch <- scrapeDuration
}

func run(c Collector, logger *slog.Logger) ([]Result, error) {
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
		HostKeyCallback: hostKeyCallback(c.module, logger),
		// Should check if hostKey algorithm is included in
		// algorithms.HostKeys.
		HostKeyAlgorithms: algorithms.HostKeys,
	}

	client, err := ssh.Dial("tcp", c.target, config)
	if err != nil {
		logger.Error("Failed to dial", "err", err)
		c.telemetry.ScrapeRequestError.Inc()
		return nil, err
	}
	defer client.Close()

	var wg sync.WaitGroup
	for i := range c.results {
		wg.Add(1)
		go func() {
			data, err := execute(client, c.module.StartShell, c.results[i].job, &wg, logger)
			if err != nil {
				logger.Error("Error executing job", "job number", i, "target", c.target, "module", c.module, "err", err)
				return
			}

			c.results[i].data = data
		}()
		wg.Wait()
	}

	return c.results, nil
}

func execute(client *ssh.Client, startShell bool, cmds []string, wg *sync.WaitGroup, logger *slog.Logger) ([]byte, error) {
	defer wg.Done()
	session, err := client.NewSession()
	if err != nil {
		logger.Error("Error creating ssh session", "err", err)
		return nil, err
	}
	defer session.Close()

	reader, err := session.StdoutPipe()
	if err != nil {
		logger.Error("Error creating session stdout pipe", "err", err)
		return nil, err
	}
	if startShell {
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,
			ssh.TTY_OP_ISPEED: 115200,
			ssh.TTY_OP_OSPEED: 115200,
		}

		if err := session.RequestPty("vt100", 100, 100, modes); err != nil {
			logger.Error("Error requestinng PTY", "err", err)
			return nil, err
		}

		stdinPipe, err := session.StdinPipe()
		if err != nil {
			logger.Error("Error creating StdinPipe with PTY session", "err", err)
			return nil, err
		}

		if err := session.Shell(); err != nil {
			logger.Error("Error starting Shell with PTY session", "err", err)
			return nil, err
		}
		go func() {
			defer stdinPipe.Close()
			for _, cmd := range cmds {
				cmd = cmd + "\n"
				_, err := stdinPipe.Write([]byte(cmd))
				if err != nil {
					logger.Error("Error writing cmd to StdinPip", "cmd", cmd, "err", err)
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()
	} else {
		cmd := strings.Join(cmds, ";")
		if err := session.Start(cmd); err != nil {
			logger.Error("Error starting command", "cmd", cmd, "err", err)
			return nil, err
		}
	}

	type outputs struct {
		bytes []byte
		err   error
	}

	waitOut := make(chan outputs, 1)
	go func() {
		bytes, err := io.ReadAll(reader)
		waitOut <- outputs{bytes: bytes, err: err}
		close(waitOut)
	}()

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- session.Wait()
		close(waitDone)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	select {
	case err := <-waitDone:
		result := <-waitOut
		if err != nil {
			logger.Warn("Non nil err returned from command starting", "cmds", cmds, "err", err)
		}
		if result.err != nil {
			logger.Error("Error reading bulk session stdout pipe", "err", err)
			return nil, err
		}
		return result.bytes, nil
	case <-ctx.Done():
		return nil, errors.New("session execution timed out; abandoning session")
	}
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

	var results []Result

	keys := []*string{&module.Password, &module.PrivateKey, &module.PrivateKeyPass, &module.Certificate}

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

	for _, job := range module.Jobs {
		metrics := make([]Metric, len(job.Metrics))
		j := 0
		for parentname, metric := range job.Metrics {
			labelnames := make([]string, len(metric.Labels))
			labelvalues := make([]string, len(metric.Labels))
			i := 0
			for k, v := range metric.Labels {
				labelnames[i] = k
				labelvalues[i] = v
				i++
			}

			gauges := make([]ConstMetric, len(metric.Gauges))
			i = 0
			for name, value := range metric.Gauges {
				fqname := strings.Join([]string{parentname, name}, "_")
				g := ConstMetric{
					desc:      prometheus.NewDesc(fqname, metric.Help, labelnames, nil),
					fqname:    fqname,
					valueType: prometheus.GaugeValue,
					value:     value,
				}
				gauges[i] = g
				i++
			}
			counters := make([]ConstMetric, len(metric.Counters))
			i = 0
			for name, value := range metric.Counters {
				fqname := strings.Join([]string{parentname, name}, "_")
				m := ConstMetric{
					desc:      prometheus.NewDesc(fqname, metric.Help, labelnames, nil),
					fqname:    fqname,
					valueType: prometheus.CounterValue,
					value:     value,
				}
				counters[i] = m
				i++
			}
			constMetrics := append(gauges, counters...)

			histograms := make([]Histogram, len(metric.Histograms))
			i = 0
			for name, value := range metric.Histograms {
				fqname := strings.Join([]string{parentname, name}, "_")
				h := Histogram{
					opts: prometheus.HistogramOpts{
						Name:                           fqname,
						Help:                           metric.Help,
						NativeHistogramBucketFactor:    metric.BucketFactor,
						NativeHistogramMaxBucketNumber: metric.BucketNumber,
					},
					value:      value,
					labelnames: labelnames,
				}
				histograms[i] = h
				i++
			}

			metric := Metric{
				name:                parentname,
				grok:                metric.GrokCompile,
				continueOnDuplicate: metric.ContineOnDuplicate,
				labelvalues:         labelvalues,
				constMetrics:        constMetrics,
				histograms:          histograms,
			}
			metrics[j] = metric
			j++
		}
		result := Result{
			job:     job.Commands,
			metrics: metrics,
		}
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
	}
}
