package main

// The agent's way to GarnetOps (ADR 0034 and 0037): HTTPS only (TLS 1.2 or newer, the certificate checked against the system store or
// a CA file), no redirects, every request after enrolment signed with the host's Ed25519 key, answers capped at 1 MiB.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const maxAnswer = 1024 * 1024

// ServerError is an answer outside 2xx; Code is the last part of the problem type ("module-off", "invalid-agent-signature").
type ServerError struct {
	Status int
	Code   string
}

func (e *ServerError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("GarnetOps answered %d (%s)", e.Status, e.Code)
	}
	return fmt.Sprintf("GarnetOps answered %d", e.Status)
}

// Identity is this host's id and private key.
type Identity struct {
	HostID     string
	PrivateKey ed25519.PrivateKey
}

// Client posts JSON to the agent API of one installation.
type Client struct {
	base *url.URL
	http *http.Client
}

// NewClient checks the address (https only) and sets up TLS.
func NewClient(baseURL, caFile string) (*Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil || base.Host == "" {
		return nil, errors.New("GARNETOPS_URL is not an address")
	}
	if base.Scheme != "https" && !(allowHTTP && base.Scheme == "http") {
		return nil, errors.New("GARNETOPS_URL must be an https:// address")
	}
	if base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("GARNETOPS_URL must be a plain address")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("GARNETOPS_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("GARNETOPS_CA_FILE holds no certificate")
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &Client{
		base: base,
		http: &http.Client{
			Transport: transport,
			Timeout:   60 * time.Second,
			// A redirect is never followed: it is an error like any other status outside 2xx.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// SigningInput is what is signed: method, path with query, time, nonce and the SHA-256 of the body, one per line
// (signingInput in @garnetops/core/agent).
func SigningInput(method, path string, timestamp int64, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(strings.Join([]string{strings.ToUpper(method), path, strconv.FormatInt(timestamp, 10), nonce, hex.EncodeToString(sum[:])}, "\n"))
}

// SignatureHeader is the Authorization header of a signed request.
func SignatureHeader(id Identity, method, path string, body []byte, now time.Time) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	timestamp := now.UnixMilli()
	sig := ed25519.Sign(id.PrivateKey, SigningInput(method, path, timestamp, nonce, body))
	return fmt.Sprintf(`GarnetOps-Agent host="%s", ts="%d", nonce="%s", sig="%s"`, id.HostID, timestamp, nonce,
		base64.RawURLEncoding.EncodeToString(sig)), nil
}

// Post sends `body` as JSON to a path under /api/v1/agent, signed when an identity is given, and decodes the answer into `out`.
func (c *Client) Post(path string, body any, id *Identity, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	full := strings.TrimRight(c.base.Path, "/") + "/api/v1/agent" + path
	target := *c.base
	target.Path = full
	req, err := http.NewRequest(http.MethodPost, target.String(), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("user-agent", "GarnetOps-Agent")
	if id != nil {
		header, err := SignatureHeader(*id, http.MethodPost, full, data, time.Now())
		if err != nil {
			return err
		}
		req.Header.Set("authorization", header)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(res.Body, maxAnswer+1))
	if err != nil {
		return err
	}
	if len(answer) > maxAnswer {
		return errors.New("answer too large")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var problem struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(answer, &problem)
		code := ""
		if problem.Type != "" {
			code = problem.Type[strings.LastIndex(problem.Type, "/")+1:]
		}
		return &ServerError{Status: res.StatusCode, Code: code}
	}
	if out == nil || len(answer) == 0 {
		return nil
	}
	return json.Unmarshal(answer, out)
}
