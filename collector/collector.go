package collector

import (
  "os"
  "context"
  "fmt"
  "log/slog"
  "math"
  "net"
  "strings"
  "strconv"
  "time"
  "errors"
  "sync"
  "io"

  "golang.org/x/crypto/ssh"
  "golang.org/x/crypto/ssh/knownhosts"
  "github.com/alecthomas/kingpin/v2"
  "github.com/prometheus/client_golang/prometheus"
  "github.com/cwkwan/ssh_exporter/config"
  "github.com/expr-lang/expr"
)

var (
  ignoreHostKey    = kingpin.Flag("ignore-host-key", "Accept any host key, insecure. hostkey.file and known_hosts_file will be ignored").Default("false").Bool()
)

type Telemetry struct {
  Desc                     *prometheus.Desc
  ScrapeCollectionDuration *prometheus.HistogramVec
  ScrapeDuration           *prometheus.HistogramVec
  ScrapeCount              prometheus.Counter
  ScrapeRequestError       prometheus.Counter
  ScrapeInflight           prometheus.Gauge
}

type Collector struct {
  name         string                    // module name
  ctx          context.Context
  target       string
  telemetry    Telemetry
  module       *config.Module
  logger       *slog.Logger
  results      []Result
}

type Result struct {
  job      string
  data     []byte
  metrics  []Metric
}

type Metric struct {
  name          string
  grok          string
  constMetrics  []ConstMetric
  histograms    []Histogram
}

type ConstMetric struct {
  desc        *prometheus.Desc
  valueType   prometheus.ValueType
  value       string
  labels      []string
}

type Histogram struct {
  opts        prometheus.HistogramOpts
  value       string
  labelnames  []string
  labels      []string
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

  start := time.Now()
  c.telemetry.ScrapeInflight.Inc()
  c.telemetry.ScrapeCount.Inc()
  results, _ := run(c, logger)
  c.telemetry.ScrapeCollectionDuration.WithLabelValues(c.name).Observe(time.Since(start).Seconds())
  c.telemetry.ScrapeInflight.Dec()

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
        for _, match := range matches {
          labelvalues := parseLabel(match, constMetric.labels)
          if value, err := toFloat(parse(match, constMetric.value)); err == nil {
            m := prometheus.MustNewConstMetric(
              constMetric.desc,
              constMetric.valueType,
              value,
              labelvalues...
            )
            ch <- m
          } else {
            logger.Error("Error converting value to float", "value", constMetric.value, "err", err)
          }
        }
      }

      for _, histogram := range metric.histograms {
        for _, match := range matches {
          labelvalues := parseLabel(match, histogram.labels)
          if value, err := toFloat(parse(match, histogram.value)); err == nil {
            if len(labelvalues) > 0 {
              m := prometheus.NewHistogramVec(histogram.opts, histogram.labelnames)
              m.WithLabelValues(labelvalues...).Observe(value)
              m.Collect(ch)
            } else {
              m := prometheus.NewHistogram(histogram.opts)
              m.Observe(value)
              m.Collect(ch)
            }
          } else {
            logger.Error("Error converting value to float", "value", histogram.value, "err", err)
          }
        }
      }
    }
  }
  logger.Debug("Finished parsing", "duration_seconds", time.Since(start).Seconds())
  c.telemetry.ScrapeDuration.WithLabelValues(c.name).Observe(time.Since(start).Seconds())
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
    User: c.module.User,
    Auth: []ssh.AuthMethod{auth},
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
  for i, _ := range c.results {
    wg.Add(1)
    go func() {
      data, err := execute(client, c.results[i].job, &wg, logger)
      if err != nil {
        logger.Error("Error with ssh command", "target", c.target, "module", c.module, "job.Command", c.results[i].job, "err", err)
        return
      }

      c.results[i].data = data
    }()
    wg.Wait()
  }

  return c.results, nil
}

func execute(client *ssh.Client, cmd string, wg *sync.WaitGroup, logger *slog.Logger) ([]byte, error) {
  defer wg.Done()
  session, err := client.NewSession()
  if err != nil {
    logger.Error("Error creating ssh session", "err", err)
    return nil, err
  }

  reader, err := session.StdoutPipe()
  if err != nil {
    logger.Error("Error creating session stdout pipe", "err", err)
    return nil, err
  }
  if err := session.Run(cmd); err != nil {
    logger.Error("Error running command", "cmd", cmd, "err", err)
    return nil, err
  }

  defer session.Close()
  bytes, err := io.ReadAll(reader)
  if err != nil {
    logger.Error("Error reading session stdout pipe", "err", err)
    return nil, err
  }

  time.Sleep(100 * time.Millisecond)

  return bytes, nil

}

func parse(rs map[string]string, value string) string {

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

func parseLabel(rs map[string]string, labels []string) []string {
  values := make([]string, len(labels))
  for i, label := range labels {
    value := parse(rs, label)
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

  if s == "<nil>" {
    return math.NaN(), nil
  }
  return v, err
}

func authMethod(m *config.Module, logger *slog.Logger) (ssh.AuthMethod, error) {
  var auth ssh.AuthMethod
  if m.Password != "" {
    auth = ssh.Password(m.Password)
  } else {
    if m.PrivateKey != "" {
      key, err := os.ReadFile(m.PrivateKey)
      if err != nil {
        logger.Error("unable to read private key", "err", err, "private_key file", m.PrivateKey)
        return nil, err
      }
      signer, err := ssh.ParsePrivateKey(key)
      if err != nil {
        logger.Error("unable to parse private key", "err", err)
        return nil, err
      }
      auth = ssh.PublicKeys(signer)
    } else {
      err := errors.New("password and private_key not specified")
      logger.Error("either password or private_key need to be provided", "err", err)
      return nil, err
    }
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

func New(ctx context.Context, target string, name string, module *config.Module, telemetry Telemetry, logger *slog.Logger) *Collector {
  var results []Result

  for _, job := range module.Jobs {
    metrics := make([]Metric, len(job.Metrics))
    j := 0
    for parentname, metric := range job.Metrics {

      labelnames := make([]string, len(metric.Labels))
      labelvalues := make([]string, len(metric.Labels))
      i := 0
      for k,v := range metric.Labels {
        labelnames[i] = k
        labelvalues[i] = v
        i++
      }

      gauges := make([]ConstMetric, len(metric.Gauges))
      i = 0
      for name, value := range metric.Gauges {
        fqname := strings.Join([]string{parentname, name}, "_")
        g := ConstMetric{
          desc: prometheus.NewDesc(fqname, metric.Help, labelnames, nil),
          valueType: prometheus.GaugeValue,
          value: value,
          labels: labelvalues,
        }
        gauges[i] = g
        i++
      }
      counters := make([]ConstMetric, len(metric.Counters))
      i = 0
      for name, value := range metric.Counters {
        fqname := strings.Join([]string{parentname, name}, "_")
        m := ConstMetric{
          desc: prometheus.NewDesc(fqname, metric.Help, labelnames, nil),
          valueType: prometheus.CounterValue,
          value: value,
          labels: labelvalues,
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
            Name: fqname,
            Help: metric.Help,
            NativeHistogramBucketFactor: metric.BucketFactor,
            NativeHistogramMaxBucketNumber: metric.BucketNumber,
          },
          value: value,
          labelnames: labelnames,
          labels: labelvalues,
        }
        histograms[i] = h
        i++
      }

      metric := Metric{
        name: parentname,
        grok: metric.GrokCompile,
        constMetrics: constMetrics,
        histograms: histograms,
      }
      metrics[j] = metric
      j++
    }
    result := Result{
      job: job.Command,
      metrics: metrics,
    }
    results = append(results, result)
  }

  return &Collector{
    name: name,
    ctx: ctx,
    target: target,
    module: module,
    telemetry: telemetry,
    logger: logger,
    results : results,
  }
}

// expand %{ }
func expand(logger *slog.Logger, s string, vars map[string]string) string {
  var buf []byte
  i := 0
  for j := 0; j < len(s); j++ {
    if s[j] == '%' && j+1 < len(s) {
      if buf == nil {
        buf = make([]byte, 0, 2*len(s))
      }
      buf = append(buf, s[i:j]...)
      name, w := getVarName(logger, s[j+1:])
      if name == "" {
        buf = append(buf, s[j])
      } else {
        buf = append(buf, vars[name]...)
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

func getVarName(logger *slog.Logger, s string) (string, int) {
  if s[0] == '{' {
    for i := 1; i < len(s) && isAlphaNum(s[i]); i++ {
      if s[i] == '}' {
        if i == 1 {
          return "", 0
        }
        return s[1:i], i+1
      }
    }
    return "", 0
  }
  return "", 0
}

func isAlphaNum(c uint8) bool {
  return c == '#' || c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}
