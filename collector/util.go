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
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/expr-lang/expr"
	"golang.org/x/crypto/ssh"
)

type sshClient struct {
	target    string
	config    *ssh.ClientConfig
	client    *ssh.Client
	telemetry *Telemetry
	mu        sync.Mutex
}

func newSSHClient(target string, config *ssh.ClientConfig, telemetry *Telemetry) *sshClient {
	return &sshClient{
		target:    target,
		config:    config,
		telemetry: telemetry,
	}
}

func (s *sshClient) clientUp(timeout time.Duration) error {

	if s.client == nil {
		return errors.New("ssh client is nil")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	respChan := make(chan error, 1)

	go func() {
		_, _, err := s.client.SendRequest("keepalive@golang.org", true, nil)
		respChan <- err
	}()

	select {
	case e := <-respChan:
		if e != nil {
			return e
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *sshClient) sessionUp(session *ssh.Session, timeout time.Duration) error {

	if session == nil {
		return errors.New("ssh session is nil")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	respChan := make(chan error, 1)

	go func() {
		_, err := session.SendRequest("keepalive@golang.org", true, nil)
		respChan <- err
	}()

	select {
	case e := <-respChan:
		if e != nil {
			session.Close()
			return e
		}
		return nil
	case <-ctx.Done():
		session.Close()
		return ctx.Err()
	}
}

func (s *sshClient) connect() (*ssh.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client != nil {
		if err := s.clientUp(s.config.Timeout); err == nil {
			return s.client, nil
		}
		_ = s.close()
		s.client = nil
	}

	client, err := ssh.Dial("tcp", s.target, s.config)
	if err != nil {
		s.telemetry.ScrapeRequestError.Inc()
		return nil, fmt.Errorf("failed to create ssh client conn: %w", err)
	}

	s.client = client
	return s.client, nil
}

func (s *sshClient) newSession() (*ssh.Session, io.Reader, error) {
	client, err := s.connect()
	if err != nil {
		return nil, nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, nil, fmt.Errorf("Error creating new ssh session: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("Error creating session stdout pipe: %w", err)
	}

	return session, stdout, nil
}

func (s *sshClient) newShellSession() (*ssh.Session, io.WriteCloser, io.Reader, error) {
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 115200,
		ssh.TTY_OP_OSPEED: 115200,
	}
	session, stdout, err := s.newSession()
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error creating session stdin pipe: %w", err)
	}
	if err := session.RequestPty("xterm", 100, 100, modes); err != nil {
		return nil, nil, nil, fmt.Errorf("Error creating interative session pty: %w", err)
	}
	if err := session.Shell(); err != nil {
		return nil, nil, nil, fmt.Errorf("Error creating interactive session shell: %w", err)
	}

	return session, stdin, stdout, nil
}

func (s *sshClient) runBulk(t int, jobs []job, logger *slog.Logger) ([][]byte, error) {
	type outputs struct {
		b   []byte
		err error
	}
	var outs [][]byte
	var wg sync.WaitGroup
	for i, job := range jobs {
		logger.Debug("Starting next job", "job", i)
		logger.Info("Sending commands in bulk", "cmds", job.maskedCmds)
		expired := false
		wg.Add(1)
		logger.Debug("Creating session", "job", i)
		session, stdout, err := s.newSession()
		if err != nil {
			return outs, err
		}
		defer session.Close()

		var output bytes.Buffer
		outChan := make(chan outputs, 1)
		timeout := time.Duration(t) * time.Millisecond
		cmdTimer := time.NewTimer(timeout)
		defer cmdTimer.Stop()
		go func() {
			for !expired {
				buf := make([]byte, 1024)
				n, err := stdout.Read(buf)
				logger.Debug("Bytes read from StdoutPipe", "bytes", n, "job", i)
				bufn := make([]byte, n)
				copy(bufn, buf[:n])
				cmdTimer.Reset(timeout)
				outChan <- outputs{b: bufn, err: err}
				if err != nil {
					logger.Debug("Err from StdoutPipe", "err", err, "job", i)
					logger.Debug("Closing session from our end", "job", i)
					break
				}
			}
			session.Close()
			close(outChan)
		}()

		cmd := strings.Join(job.cmds, ";")
		if err := session.Start(cmd); err != nil {
			return outs, fmt.Errorf("Error starting command: %q, err: %w", job.maskedCmds, err)
		}
	WaitOut:
		for {
			select {
			case out := <-outChan:
				output.Write(out.b)
				if out.err != nil {
					break WaitOut
				}
			case <-cmdTimer.C:
				logger.Debug("cmd_timeout reached", "cmd_timeout", t, "job", i)
				break WaitOut
			}
		}
		outs = append(outs, output.Bytes())
		cmdTimer.Stop()
		expired = true
		wg.Done()
	}
	wg.Wait()
	return outs, nil
}

// RunInteractiveWaitTimeOut uses a fixed timeout throughtout the session.
//
// It will retun output until error. But error from stdout or session
// termination will not be returned, error will only be returned when
// it happened during setup of session, the shell, or when issuing
// the commands.
func (s *sshClient) runShellWaitTimeOut(t int, jobs []job, logger *slog.Logger) ([][]byte, error) {
	type outputs struct {
		b   []byte
		err error
	}
	var outs [][]byte
	var session *ssh.Session
	var stdin io.WriteCloser
	var stdout io.Reader

	outChan := make(chan outputs, 1)
	timeout := time.Duration(t) * time.Millisecond
	cmdTimer := time.NewTimer(timeout)
	defer cmdTimer.Stop()
	cmdTimer.Stop()
	for i, job := range jobs {
		var output bytes.Buffer
		logger.Debug("Starting next job", "job", i)
		logger.Info("Sending commands in shell", "cmds", job.maskedCmds)
		if err := s.sessionUp(session, timeout); err != nil {
			logger.Debug("No existing session, creating session", "job", i)
			session, stdin, stdout, err = s.newShellSession()
			if err != nil {
				return outs, err
			}
			defer session.Close()

			cmdTimer.Reset(timeout)
			go func() {
				for {
					buf := make([]byte, 1024)
					n, err := stdout.Read(buf)
					logger.Debug("Bytes read from StdoutPipe", "bytes", n, "job", i)
					bufn := make([]byte, n)
					copy(bufn, buf[:n])
					cmdTimer.Reset(timeout)
					outChan <- outputs{b: bufn, err: err}
					if err != nil {
						logger.Debug("Err from StdoutPipe", "err", err, "job", i)
						logger.Debug("Closing session from our end", "job", i)
						break
					}
				}
				session.Close()
			}()
		}

		logger.Debug("Write cmd to StdinPipe", "cmds", job.cmds, "job", i)
		for _, cmd := range job.cmds {
			cmd = cmd + "\n"
			_, err := stdin.Write([]byte(cmd))
			if err != nil {
				logger.Debug("Err from StdinPipe", "err", err, "job", i)
				outs = append(outs, make([]byte, 0))
				return outs, fmt.Errorf("Error writing cmd to session stdin pipe: %w", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	WaitOut:
		for {
			select {
			case out := <-outChan:
				output.Write(out.b)
				if out.err != nil {
					break WaitOut
				}
			case <-cmdTimer.C:
				logger.Debug("cmd_timeout reached", "cmd_timeout", t, "job", i)
				break WaitOut
			}
		}
		cmdTimer.Stop()
		outs = append(outs, output.Bytes())
	flushOut:
		for {
			select {
			case _, ok := <-outChan:
				if !ok {
					break flushOut
				}
			default:
				break flushOut
			}
		}
	}
	return outs, nil
}

func (s *sshClient) runShellWaitEof(t int, re *regexp.Regexp, jobs []job, logger *slog.Logger) ([][]byte, error) {
	type outputs struct {
		b   []byte
		err error
	}
	var outs [][]byte
	var session *ssh.Session
	var stdin io.WriteCloser
	var stdout io.Reader

	outChan := make(chan outputs, 1)
	timeout := time.Duration(t) * time.Millisecond
	cmdTimer := time.NewTimer(time.Second)
	defer cmdTimer.Stop()
	cmdTimer.Stop()
	for i, job := range jobs {
		var output bytes.Buffer
		readTimeout := time.NewTimer(200 * time.Millisecond)
		defer readTimeout.Stop()
		readTimeout.Stop()
		logger.Debug("Starting next job", "job", i)
		logger.Info("Sending commands in shell", "cmds", job.maskedCmds)
		if err := s.sessionUp(session, timeout); err != nil {
			logger.Debug("No existing session, creating session", "job", i)
			session, stdin, stdout, err = s.newShellSession()
			if err != nil {
				return outs, err
			}
			defer session.Close()

			cmdTimer.Reset(timeout)
			readTimeout.Reset(200 * time.Millisecond)
			go func() {
				for {
					buf := make([]byte, 1024)
					n, err := stdout.Read(buf)
					logger.Debug("Bytes read from StdoutPipe", "bytes", n, "job", i)
					bufn := make([]byte, n)
					copy(bufn, buf[:n])
					cmdTimer.Reset(timeout)
					readTimeout.Reset(200 * time.Millisecond)
					outChan <- outputs{b: bufn, err: err}
					if err != nil {
						logger.Debug("Err from StdoutPipe", "err", err, "job", i)
						logger.Debug("Closing session from our end", "job", i)
						break
					}
				}
				session.Close()
			}()
		}
		logger.Debug("Write cmd to StdinPipe", "cmds", job.cmds, "job", i)
		for _, cmd := range job.cmds {
			cmd = cmd + "\n"
			_, err := stdin.Write([]byte(cmd))
			if err != nil {
				logger.Debug("Err from StdinPipe", "err", err, "job", i)
				outs = append(outs, make([]byte, 0))
				return outs, fmt.Errorf("Error writing cmd to session stdin pipe: %w", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	WaitOut:
		for {
			select {
			case <-cmdTimer.C:
				logger.Debug("cmd_timeout reached", "cmd_timeout", t, "job", i)
				break WaitOut
			default:
			}
			select {
			case out := <-outChan:
				output.Write(out.b)
				if out.err != nil {
					break WaitOut
				}
			case <-readTimeout.C:
				m := re.FindIndex(output.Bytes())
				if m != nil {
					logger.Debug("eof matched", "eof", re.String(), "job", i)
					break WaitOut
				}
			}
		}
		outs = append(outs, output.Bytes())
		cmdTimer.Stop()
		readTimeout.Stop()
	flushOut:
		for {
			select {
			case _, ok := <-outChan:
				if !ok {
					break flushOut
				}
			default:
				break flushOut
			}
		}
	}
	return outs, nil
}

func (s *sshClient) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client != nil {
		err := s.client.Close()
		s.client = nil
		return err
	}
	return nil
}

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

func compile(rs map[string]string, exp string) string {
	program, err := expr.Compile(exp, expr.Env(rs))
	if err != nil {
		return exp
	}
	v, err := expr.Run(program, rs)
	if err != nil {
		return exp
	}

	return fmt.Sprint(v)
}

func parse(rs map[string]string, exp string) (float64, error) {
	if v, err := toFloat(exp); err != nil {
		return toFloat(compile(rs, exp))
	} else {
		return v, nil
	}
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

	if t, err := strconv.ParseBool(s); err == nil {
		if t {
			return 1.0, nil
		} else {
			return 0.0, nil
		}
	} else {
		return math.NaN(), err
	}
}
