// Package main implements the microvm-policy egress proxy: the enforcement
// half of EGRESS_POLICY (the shadow and enforce rungs). It knows nothing
// about microVMs — a JSON config in, a JSONL audit log out — so any
// consumer's launcher can drive it.
package main

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Allowlist decides which host:port pairs an opaque CONNECT tunnel (or a
// plain-HTTP forward request) may reach.
//
// The file format is the one allowlists/ and egress-report.sh
// already share: one entry per line, '#' starts a comment, an entry matches
// itself and every subdomain, and a leading "*." is tolerated and ignored.
// The proxy adds one reading the observe-only modes ignore: an entry may
// carry an explicit ":port" (e.g. "github.com:22" for git over SSH), and a
// bare entry grants port 443 only. Ports are capability grants, so they are
// opt-in per entry rather than global. Entries are domains or IPv4 literals;
// bracketless IPv6 literals would collide with the port syntax and are not
// supported.
type Allowlist struct {
	ports map[string]map[int]bool
}

const defaultAllowedPort = 443

func ParseAllowlist(r io.Reader) (*Allowlist, error) {
	a := &Allowlist{ports: make(map[string]map[int]bool)}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		host, port, ok := parseEntry(line)
		if !ok {
			continue
		}
		if a.ports[host] == nil {
			a.ports[host] = make(map[int]bool)
		}
		a.ports[host][port] = true
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return a, nil
}

// parseEntry reads one comment-stripped line. ok is false for blank lines and
// for entries that cannot be parsed: a garbled entry must not widen the list.
func parseEntry(line string) (host string, port int, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", 0, false
	}
	host, port = line, defaultAllowedPort
	if i := strings.LastIndexByte(line, ':'); i >= 0 {
		n, err := strconv.Atoi(line[i+1:])
		if err != nil || n <= 0 || n >= 65536 {
			return "", 0, false
		}
		host, port = line[:i], n
	}
	host = normalizeHost(strings.TrimPrefix(host, "*."))
	return host, port, host != ""
}

func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// Allowed reports whether host:port may be reached. A pattern matches itself
// and every subdomain, and the port must have been granted on the matching
// entry — a port granted to one host widens nothing else.
func (a *Allowlist) Allowed(host string, port int) bool {
	host = normalizeHost(host)
	for pat, ports := range a.ports {
		if (host == pat || strings.HasSuffix(host, "."+pat)) && ports[port] {
			return true
		}
	}
	return false
}
