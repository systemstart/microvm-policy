package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newTestProxy(t *testing.T, mode, allowlist string, endpoints []*Endpoint) (*httptest.Server, *syncBuf) {
	t.Helper()
	a, err := ParseAllowlist(strings.NewReader(allowlist))
	if err != nil {
		t.Fatal(err)
	}
	audit := &syncBuf{}
	p := &Proxy{
		mode:      mode,
		allow:     a,
		endpoints: endpoints,
		audit:     slog.New(slog.NewJSONHandler(audit, nil)),
		transport: http.DefaultTransport,
	}
	ts := httptest.NewServer(p)
	t.Cleanup(ts.Close)
	return ts, audit
}

func anthropicEndpoint(t *testing.T, upstream string) *Endpoint {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	return &Endpoint{
		Prefix:       "/anthropic",
		Upstream:     upstream,
		Header:       "x-api-key",
		AllowedPaths: []string{"/v1/messages"},
		upstreamURL:  u,
		key:          "proxy-held-key",
	}
}

func TestEndpointStripsAndInjects(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Api-Key"); got != "proxy-held-key" {
			t.Errorf("X-Api-Key = %q, want the injected key", got)
		}
		for _, h := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
			if got := r.Header.Get(h); got != "" {
				t.Errorf("%s = %q, want it stripped", h, got)
			}
		}
		if r.URL.Path != "/v1/messages" {
			t.Errorf("upstream path = %q, want /v1/messages", r.URL.Path)
		}
		if r.URL.RawQuery != "beta=true" {
			t.Errorf("query = %q, want beta=true", r.URL.RawQuery)
		}
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	}))
	defer backend.Close()

	ts, _ := newTestProxy(t, "enforce", "", []*Endpoint{anthropicEndpoint(t, backend.URL)})

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/anthropic/v1/messages?beta=true", strings.NewReader("prompt"))
	// A planted credential riding on an allowed connection must not survive.
	req.Header.Set("X-Api-Key", "attacker-planted")
	req.Header.Set("Authorization", "Bearer stolen")
	req.Header.Set("Cookie", "session=stolen")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body, _ := io.ReadAll(resp.Body); string(body) != "prompt" {
		t.Errorf("body = %q, want it round-tripped", body)
	}
}

func TestEndpointPathAllowlist(t *testing.T) {
	var backendHits int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits++
	}))
	defer backend.Close()

	t.Run("enforce denies off-list paths", func(t *testing.T) {
		ts, audit := newTestProxy(t, "enforce", "", []*Endpoint{anthropicEndpoint(t, backend.URL)})
		resp, err := http.Get(ts.URL + "/anthropic/v1/files")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "denied") || !strings.Contains(string(body), "/v1/messages") {
			t.Errorf("denial must name the allowed paths, got %q", body)
		}
		if !strings.Contains(audit.String(), `"decision":"deny"`) {
			t.Errorf("audit log missing deny entry: %s", audit.String())
		}
	})

	t.Run("log mode allows and audits would_deny", func(t *testing.T) {
		before := backendHits
		ts, audit := newTestProxy(t, "log", "", []*Endpoint{anthropicEndpoint(t, backend.URL)})
		resp, err := http.Get(ts.URL + "/anthropic/v1/files")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 in log mode", resp.StatusCode)
		}
		if backendHits != before+1 {
			t.Error("log mode must still reach the backend")
		}
		if !strings.Contains(audit.String(), `"decision":"would_deny"`) {
			t.Errorf("audit log missing would_deny entry: %s", audit.String())
		}
	})

	t.Run("sub-paths of an allowed prefix pass", func(t *testing.T) {
		ts, _ := newTestProxy(t, "enforce", "", []*Endpoint{anthropicEndpoint(t, backend.URL)})
		resp, err := http.Get(ts.URL + "/anthropic/v1/messages/count_tokens")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("dot-dot cannot escape the allowed subtree", func(t *testing.T) {
		ts, _ := newTestProxy(t, "enforce", "", []*Endpoint{anthropicEndpoint(t, backend.URL)})
		// Sent raw: the Go client would clean the path before it left.
		conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		fmt.Fprintf(conn, "GET /anthropic/v1/messages/../files HTTP/1.1\r\nHost: x\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 for the cleaned path /v1/files", resp.StatusCode)
		}
	})
}

func TestConnect(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	target := echo.Addr().String()

	connect := func(t *testing.T, proxyURL, target string) (*http.Response, net.Conn, *bufio.Reader) {
		t.Helper()
		conn, err := net.Dial("tcp", strings.TrimPrefix(proxyURL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatal(err)
		}
		return resp, conn, br
	}

	t.Run("allowlisted host:port tunnels", func(t *testing.T) {
		ts, _ := newTestProxy(t, "enforce", target+"\n", nil)
		resp, conn, br := connect(t, ts.URL, target)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
		}
		if _, err := conn.Write([]byte("ping\n")); err != nil {
			t.Fatal(err)
		}
		line, err := br.ReadString('\n')
		if err != nil || line != "ping\n" {
			t.Fatalf("echo through tunnel = %q, %v", line, err)
		}
	})

	t.Run("off-list host is denied with an actionable message", func(t *testing.T) {
		ts, audit := newTestProxy(t, "enforce", target+"\n", nil)
		resp, _, _ := connect(t, ts.URL, "evil.example.com:443")
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("CONNECT status = %d, want 403", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "not in the allowlist") || !strings.Contains(string(body), "EGRESS_ALLOW=evil.example.com") {
			t.Errorf("denial not actionable: %q", body)
		}
		if !strings.Contains(audit.String(), `"host":"evil.example.com"`) {
			t.Errorf("audit log missing the denied host: %s", audit.String())
		}
	})

	t.Run("allowed host on a different port is denied", func(t *testing.T) {
		host, _ := splitHostPort(target, 0)
		ts, _ := newTestProxy(t, "enforce", target+"\n", nil)
		resp, _, _ := connect(t, ts.URL, net.JoinHostPort(host, "1"))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("CONNECT status = %d, want 403: ports are per-entry grants", resp.StatusCode)
		}
	})
}

func TestForwardHTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "forwarded")
	}))
	defer backend.Close()
	backendHostPort := strings.TrimPrefix(backend.URL, "http://")

	ts, _ := newTestProxy(t, "enforce", backendHostPort+"\n", nil)
	proxyURL, _ := url.Parse(ts.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "forwarded" {
		t.Fatalf("forwarded GET = %d %q, want 200 forwarded", resp.StatusCode, body)
	}

	resp, err = client.Get("http://evil.example.com:80/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("off-list forward = %d, want 403", resp.StatusCode)
	}
}

func TestEndpointCustomHeader(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Goog-Api-Key"); got != "gemini-key" {
			t.Errorf("X-Goog-Api-Key = %q, want the injected key", got)
		}
	}))
	defer backend.Close()
	ep := anthropicEndpoint(t, backend.URL)
	ep.Header = "x-goog-api-key"
	ep.key = "gemini-key"
	ts, _ := newTestProxy(t, "enforce", "", []*Endpoint{ep})
	resp, err := http.Get(ts.URL + "/anthropic/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestEndpointOAuthPassthrough(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer client-oauth-token" {
			t.Errorf("Authorization = %q, want the client token passed through", got)
		}
		if got := r.Header.Get("Proxy-Authorization"); got != "" {
			t.Errorf("Proxy-Authorization = %q, want it stripped even in passthrough", got)
		}
	}))
	defer backend.Close()
	ep := anthropicEndpoint(t, backend.URL)
	ep.key = "" // OAuth mode: the client holds its own token
	ts, _ := newTestProxy(t, "enforce", "", []*Endpoint{ep})
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/anthropic/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer client-oauth-token")
	req.Header.Set("Proxy-Authorization", "Basic proxy-cred")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	allowlist := filepath.Join(dir, "allow.txt")
	os.WriteFile(allowlist, []byte("github.com\n"), 0o600)
	config := filepath.Join(dir, "config.json")

	write := func(mode, keyEnv string) {
		cfg := fmt.Sprintf(`{
  "listen": "127.0.0.1:0",
  "mode": %q,
  "allowlistFile": %q,
  "portFile": "",
  "endpoints": [{
    "prefix": "/anthropic",
    "upstream": "https://api.anthropic.com",
    "keyEnv": %q,
    "header": "x-api-key",
    "allowedPaths": ["/v1/messages"]
  }]
}`, mode, allowlist, keyEnv)
		os.WriteFile(config, []byte(cfg), 0o600)
	}

	t.Setenv("EGRESS_TEST_KEY", "k")
	write("enforce", "EGRESS_TEST_KEY")
	if _, _, err := load(config); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}

	write("enforce", "EGRESS_TEST_MISSING")
	if _, _, err := load(config); err == nil || !strings.Contains(err.Error(), "EGRESS_TEST_MISSING") {
		t.Errorf("missing credential env must fail the launch, got %v", err)
	}

	write("observe", "EGRESS_TEST_KEY")
	if _, _, err := load(config); err == nil {
		t.Error("unknown mode must be rejected")
	}
}
