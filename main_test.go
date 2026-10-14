package main

import (
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gliderlabs/ssh"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/promslog"
	terminal "golang.org/x/term"

	"github.com/cwkwan/ssh_exporter/collector"
)

func TestHandler(t *testing.T) {
	sshd := &ssh.Server{
		Addr: ":2222",
		Handler: func(s ssh.Session) {
			rawCmd := s.RawCommand()
			out := ""
			if rawCmd != "" {
				fields := strings.Fields(rawCmd)
				if len(fields) == 0 {
					return
				}

				baseCmd := fields[0] // E.g., "cat"
				args := fields[1:]   // E.g., ["/etc/passwd"]
				switch baseCmd {
				case "exit", "logout":
					io.WriteString(s, "logout\r\n")
					return
				case "df":
					out = "Filesystem                         1K-blocks       Used   Available Use% Mounted on\r\n" +
						"/dev/mapper/pve-vm--171--disk--0     8154588     757248     6961528  10% /\r\n" +
						"zfsdata                          50721331072 8136697344 42584633728  17% /mnt/Workspace\r\n" +
						"none                                     492          4         488   1% /dev\r\n" +
						"udev                                32558648          0    32558648   0% /dev/tty\r\n" +
						"tmpfs                               32599376          0    32599376   0% /dev/shm\r\n" +
						"tmpfs                               13039752        108    13039644   1% /run\r\n" +
						"tmpfs                                   5120          0        5120   0% /run/lock\r\n" +
						"tmpfs                               32599380          0    32599380   0% /tmp\r\n" +
						"tmpfs                                6519872          4     6519868   1% /run/user/0\r\n"
					io.WriteString(s, out)
				case "ping":
					if len(args) == 0 {
						out = "ping: missing host operand\r\n"
					} else {
						target := args[0]
						out = fmt.Sprintf("PING %s (%s) 56(84) bytes of data.\r\n", target, target) +
							fmt.Sprintf("64 bytes from %s: icmp_seq=1 ttl=64 time=0.042 ms\r\n", target) +
							fmt.Sprintf("64 bytes from %s: icmp_seq=2 ttl=64 time=0.045 ms\r\n", target) +
							"--- ping statistics ---\r\n2 packets transmitted, 2 received, 0% packet loss\r\n"
					}
					io.WriteString(s, out)
				default:
					io.WriteString(s, fmt.Sprintf("bash: %s: command not found\r\n", baseCmd))
				}
				return
			}

			term := terminal.NewTerminal(s,
				fmt.Sprintf("/%s/ > ", s.User()))

			pty, winCh, isPty := s.Pty()
			if isPty {
				_ = pty
				go func() {
					for chInfo := range winCh {
						_ = term.SetSize(chInfo.Width, chInfo.Height)
					}
				}()
			}

			for {
				line, err := term.ReadLine()
				if err == io.EOF {
					_, _ = io.WriteString(s, "EOF.\n")
					break
				}

				fields := strings.Fields(line)
				if len(fields) == 0 {
					continue
				}

				baseCmd := fields[0] // E.g., "cat"
				args := fields[1:]   // E.g., ["/etc/passwd"]

				log.Printf("User [%s] executing command: %s with args: %v\n", s.User(), baseCmd, args)

				// 2. Route commands and evaluate arguments
				switch baseCmd {
				case "exit", "logout":
					term.Write([]byte("logout\r\n"))
					return
				case "df":
					term.Write([]byte("Filesystem                         1K-blocks       Used   Available Use% Mounted on\r\n"))
					term.Write([]byte("/dev/mapper/pve-vm--171--disk--0     8154588     757248     6961528  10% /\r\n"))
					term.Write([]byte("zfsdata                          50721331072 8136697344 42584633728  17% /mnt/Workspace\r\n"))
					term.Write([]byte("none                                     492          4         488   1% /dev\r\n"))
					term.Write([]byte("udev                                32558648          0    32558648   0% /dev/tty\r\n"))
					term.Write([]byte("tmpfs                               32599376          0    32599376   0% /dev/shm\r\n"))
					term.Write([]byte("tmpfs                               13039752        108    13039644   1% /run\r\n"))
					term.Write([]byte("tmpfs                                   5120          0        5120   0% /run/lock\r\n"))
					term.Write([]byte("tmpfs                               32599380          0    32599380   0% /tmp\r\n"))
					term.Write([]byte("tmpfs                                6519872          4     6519868   1% /run/user/0\r\n"))
				case "ping":
					if len(args) == 0 {
						term.Write([]byte("ping: missing host operand\r\n"))
					} else {
						target := args[0]
						term.Write([]byte(fmt.Sprintf("PING %s (%s) 56(84) bytes of data.\r\n", target, target)))
						term.Write([]byte(fmt.Sprintf("64 bytes from %s: icmp_seq=1 ttl=64 time=0.042 ms\r\n", target)))
						term.Write([]byte(fmt.Sprintf("64 bytes from %s: icmp_seq=2 ttl=64 time=0.045 ms\r\n", target)))
						term.Write([]byte("--- ping statistics ---\r\n2 packets transmitted, 2 received, 0% packet loss\r\n"))
					}

				default:
					term.Write([]byte(fmt.Sprintf("bash: %s: command not found\r\n", baseCmd)))
				}
			}
		},
		PasswordHandler: func(ctx ssh.Context, password string) bool {
			username := ctx.User()
			if username == "user" && password == "password" {
				return true
			}
			return false
		},
	}

	if err := sshd.SetOption(ssh.HostKeyFile("./id_ed25519_host")); err != nil {
		log.Fatalf("Failed to set host key file: %v", err)
	}

	go func() {
		if err := sshd.ListenAndServe(); err != nil && err != ssh.ErrServerClosed {
			t.Fatalf("Failed to start PasswordAuth sshd: %v", err)
		}
	}()
	t.Cleanup(func() {
		sshd.Close()
	})

	telemetry := &collector.Telemetry{
		ScrapeRequestError: scrapeRequestError,
		ScrapeCollectDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:                        "scrape_collect_duration_seconds",
				Help:                        "Total time taken from dialing to completed ssh session, before parsing.",
				NativeHistogramBucketFactor: 1.1,
			},
			[]string{"module"},
		),
		ScrapeDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:                        "scrape_duration_seconds",
				Help:                        "Total time taken from dialing to completed parsing.",
				NativeHistogramBucketFactor: 1.1,
			},
			[]string{"module"},
		),
		ScrapeCount: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "scrape_count_total",
				Help: "Number of scrape sent.",
			},
		),
		ScrapeInflight: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "scrape_in_flight",
				Help: "Current number of scrapes being requested.",
			},
		),
	}
	if err := sc.ReloadConfig("./config.yaml"); err != nil {
		t.Fatalf("Error loading config: %s", err)
	}

	req := httptest.NewRequest("GET", "/probe?module=udev&target=127.0.0.1:2222", nil)
	recorder := httptest.NewRecorder()
	handler(recorder, req, promslog.NewNopLogger(), telemetry)

	resp := recorder.Result()
	body, _ := io.ReadAll(resp.Body)

	t.Log(string(body))
}
