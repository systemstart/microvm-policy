package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// keyFileMaxBytes bounds the credential file: a token, a timestamp.
const keyFileMaxBytes = 64 << 10

// keyFileSkew is how long before expires_at a credential stops being used:
// it must still be valid when the upstream checks it.
const keyFileSkew = 10 * time.Second

// fileCredential is a KeyFile's content.
type fileCredential struct {
	Value     string `json:"value"`
	ExpiresAt string `json:"expires_at"`
}

// fileKey reads the endpoint's KeyFile and returns the credential, or why it
// is not usable now. Read on every request: the refresher replaces it, and
// a credential cached here would outlive its file.
func (ep *Endpoint) fileKey() (string, error) {
	info, err := os.Stat(ep.KeyFile)
	if err != nil {
		return "", fmt.Errorf("no credential file: %w", err)
	}
	if info.Size() > keyFileMaxBytes {
		return "", errors.New("the credential file is larger than a credential")
	}
	raw, err := os.ReadFile(ep.KeyFile)
	if err != nil {
		return "", fmt.Errorf("unreadable credential file: %w", err)
	}
	var c fileCredential
	if err := json.Unmarshal(raw, &c); err != nil {
		return "", fmt.Errorf("malformed credential file: %w", err)
	}
	if c.Value == "" {
		return "", errors.New("the credential file holds no value")
	}
	exp, err := time.Parse(time.RFC3339, c.ExpiresAt)
	if err != nil {
		return "", fmt.Errorf("the credential file has no usable expires_at: %w", err)
	}
	if !ep.now().Add(keyFileSkew).Before(exp) {
		return "", fmt.Errorf("the credential expired at %s", exp.Format(time.RFC3339))
	}
	return c.Value, nil
}

// initKeyFile checks a KeyFile endpoint at start. The file is not read here:
// a refresher may not have written it yet. Every request reads it, and
// refuses while it is not usable.
func (ep *Endpoint) initKeyFile() error {
	if ep.KeyFile == "" {
		return nil
	}
	if ep.KeyEnv != "" {
		return errors.New("keyEnv and keyFile are exclusive: one endpoint holds one credential")
	}
	if !filepath.IsAbs(ep.KeyFile) {
		return fmt.Errorf("keyFile must be an absolute path, got %q", ep.KeyFile)
	}
	if ep.now == nil {
		ep.now = time.Now
	}
	return nil
}
