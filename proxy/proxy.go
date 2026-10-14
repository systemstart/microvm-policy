package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
)

type Proxy struct {
	mode      string // "enforce" or "log"
	allow     *Allowlist
	endpoints []*Endpoint
	audit     *slog.Logger
	transport http.RoundTripper
}

// decide maps an allowlist verdict to this mode's action. Log mode is the
// shadow rung: the denial is recorded, nothing is blocked.
func (p *Proxy) decide(allowed bool) string {
	if allowed {
		return "allow"
	}
	if p.mode == "log" {
		return "would_deny"
	}
	return "deny"
}

func (p *Proxy) log(kind, host string, port int, pathStr, decision string) {
	p.audit.LogAttrs(context.Background(), slog.LevelInfo, "decision",
		slog.String("kind", kind),
		slog.String("host", host),
		slog.Int("port", port),
		slog.String("path", pathStr),
		slog.String("decision", decision),
		slog.String("mode", p.mode),
	)
}

// Rule 2 of the policy track: every denial is loud, actionable, and legible
// to the agent reading it, not just to the human.
func denyMsg(what, host string) string {
	return fmt.Sprintf("egress-proxy: %s denied: %s is not in the allowlist — add a line to the allowlist file or EGRESS_ALLOW=%s, or launch with EGRESS_POLICY=open", what, host, host)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	// Absolute-form means the client is using us as its HTTP proxy for a
	// plain-http URL. Origin-form means a BASE_URL pointed directly here —
	// the deployment sets NO_PROXY for the proxy's own address, so endpoint
	// traffic never arrives absolute-form.
	if r.URL.IsAbs() {
		p.serveForwardHTTP(w, r)
		return
	}
	for _, ep := range p.endpoints {
		if r.URL.Path == ep.Prefix || strings.HasPrefix(r.URL.Path, ep.Prefix+"/") {
			p.serveEndpoint(ep, w, r)
			return
		}
	}
	prefixes := make([]string, len(p.endpoints))
	for i, ep := range p.endpoints {
		prefixes[i] = ep.Prefix
	}
	http.Error(w, "egress-proxy: unknown path "+r.URL.Path+" — reverse-proxied endpoints are "+strings.Join(prefixes, ", "), http.StatusNotFound)
}

// --- opaque CONNECT tunnel, never decrypted ---

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPort(r.Host, 443)
	decision := p.decide(p.allow.Allowed(host, port))
	p.log("connect", host, port, "", decision)
	if decision == "deny" {
		http.Error(w, denyMsg("CONNECT "+r.Host, host), http.StatusForbidden)
		return
	}
	upstream, err := p.dialContext(r.Context(), host, port)
	if err != nil {
		http.Error(w, "egress-proxy: cannot reach "+r.Host+": "+err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "egress-proxy: connection cannot be hijacked", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	buf.Flush()
	go func() {
		// buf's read side drains bytes the client sent early, then the conn.
		io.Copy(upstream, buf)
		upstream.Close()
	}()
	io.Copy(client, upstream)
	client.Close()
}

// dialContext opens the raw tunnel leg, chaining through the host's own
// proxy environment when one is set, so corporate upstream proxies work.
func (p *Proxy) dialContext(ctx context.Context, host string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	proxyURL, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: addr}})
	if err != nil || proxyURL == nil {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	paddr := proxyURL.Host
	if proxyURL.Port() == "" {
		port := "80"
		if proxyURL.Scheme == "https" {
			port = "443"
		}
		paddr = net.JoinHostPort(proxyURL.Hostname(), port)
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", paddr)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy %s: %w", paddr, err)
	}
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy %s: %w", paddr, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy %s refused CONNECT %s: %s", paddr, addr, resp.Status)
	}
	return &bufferedConn{Conn: conn, r: br}, nil
}

// bufferedConn keeps bytes the upstream proxy's reader buffered past its
// CONNECT response from being lost.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// --- reverse-proxied LLM endpoints ---

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Te",
	"Trailer", "Transfer-Encoding", "Upgrade",
}

// Client-supplied credentials never pass through: in Anthropic's containment
// disclosure an attacker planted a key in the workspace and rode out over an
// allowed host. Strip everything credential-shaped, then inject our own.
var credentialHeaders = []string{
	"Authorization", "X-Api-Key", "Proxy-Authorization", "Cookie",
}

func (p *Proxy) serveEndpoint(ep *Endpoint, w http.ResponseWriter, r *http.Request) {
	// path.Clean defeats /../ hops out of the allowed subtree; the server
	// hands us the path decoded, so encoded dots are already visible here.
	rest := path.Clean("/" + strings.TrimPrefix(r.URL.Path, ep.Prefix))
	decision := p.decide(pathAllowed(ep.AllowedPaths, rest))
	p.log("api", ep.upstreamURL.Host, 0, rest, decision)
	if decision == "deny" {
		http.Error(w, fmt.Sprintf(
			"egress-proxy: %s %s denied: allowed paths on %s are %s — the path allowlist is a capability grant; extend the proxy config if this endpoint is genuinely needed",
			r.Method, rest, ep.upstreamURL.Host, strings.Join(ep.AllowedPaths, ", ")),
			http.StatusForbidden)
		return
	}
	out := r.Clone(r.Context())
	out.URL = &url.URL{
		Scheme:   ep.upstreamURL.Scheme,
		Host:     ep.upstreamURL.Host,
		Path:     rest,
		RawQuery: r.URL.RawQuery,
	}
	out.Host = ep.upstreamURL.Host
	out.RequestURI = "" // outgoing requests must not carry the server form
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	// Proxy-directed auth never travels upstream in either mode.
	out.Header.Del("Proxy-Authorization")
	if ep.key != "" {
		for _, h := range credentialHeaders {
			out.Header.Del(h)
		}
		if ep.Header == "authorization" {
			out.Header.Set("Authorization", "Bearer "+ep.key)
		} else {
			out.Header.Set(http.CanonicalHeaderKey(ep.Header), ep.key)
		}
	}
	// With no key held (OAuth mode) the client's own token passes through:
	// the path allowlist still applies, but a planted credential cannot be
	// stripped when the legitimate one travels in the same header. API-key
	// mode gets the full guarantee; say so rather than imply otherwise.
	p.roundTrip(w, out)
}

func pathAllowed(allowed []string, rest string) bool {
	for _, a := range allowed {
		if rest == a || strings.HasPrefix(rest, a+"/") {
			return true
		}
	}
	return false
}

// --- plain-HTTP forward proxying (absolute-form requests) ---

func (p *Proxy) serveForwardHTTP(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPort(r.URL.Host, 80)
	decision := p.decide(p.allow.Allowed(host, port))
	p.log("http", host, port, r.URL.Path, decision)
	if decision == "deny" {
		http.Error(w, denyMsg(r.Method+" "+r.URL.String(), host), http.StatusForbidden)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	// No credential handling here: like the CONNECT tunnel, third-party
	// traffic passes untouched — the proxy manages credentials only for the
	// endpoints it owns.
	p.roundTrip(w, out)
}

func (p *Proxy) roundTrip(w http.ResponseWriter, out *http.Request) {
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "egress-proxy: upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	hdr := w.Header()
	for k, vv := range resp.Header {
		for _, v := range vv {
			hdr.Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// The Claude API streams SSE: hand chunks on as they arrive.
	io.Copy(&flushWriter{w: w}, resp.Body)
}

type flushWriter struct{ w http.ResponseWriter }

func (f *flushWriter) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err
}

func splitHostPort(hostport string, def int) (string, int) {
	h, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, def
	}
	n, err := strconv.Atoi(ps)
	if err != nil {
		return h, def
	}
	return h, n
}
