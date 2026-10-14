package main

import (
	"strings"
	"testing"
)

func TestAllowlist(t *testing.T) {
	src := `
# full-line comment
anthropic.com            # inline comment
*.example.net:8443
github.com
github.com:22
PyPI.org.
bad.example.org:notaport
`
	a, err := ParseAllowlist(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"anthropic.com", 443, true},
		{"api.anthropic.com", 443, true},
		{"API.Anthropic.COM.", 443, true},
		{"anthropic.com", 80, false},    // bare entry grants 443 only
		{"notanthropic.com", 443, false},
		{"evil-anthropic.com", 443, false}, // suffix match is label-bounded
		{"example.net", 8443, true},
		{"sub.example.net", 8443, true},
		{"example.net", 443, false},     // :port entry grants that port only
		{"github.com", 443, true},
		{"github.com", 22, true},        // two entries merge per host
		{"gist.github.com", 22, true},
		{"pypi.org", 443, true},
		{"bad.example.org", 443, false}, // garbled port must not widen
	}
	for _, c := range cases {
		if got := a.Allowed(c.host, c.port); got != c.want {
			t.Errorf("Allowed(%q, %d) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
}
