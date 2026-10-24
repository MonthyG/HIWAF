package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manager.json")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	return p
}

func TestLoopback(t *testing.T) {
	for listen, want := range map[string]bool{
		"127.0.0.1:9000": true,
		"[::1]:9000":     true,
		"localhost:9000": true,
		"127.0.0.2:9000": true,
		":9000":          false,
		"0.0.0.0:9000":   false,
		"[::]:9000":      false,
		"10.0.0.1:9000":  false,
		"example.com:80": false,
		"9000":           false,
	} {
		assert.Equal(t, want, loopback(listen), listen)
	}
}

func TestDevKeyRefusedOffLoopback(t *testing.T) {
	_, err := loadConfig(writeConfig(t, `{"listen":"0.0.0.0:9000","api_keys":["change-me-dev-key"]}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "change-me-dev-key")

	// The default listen address (":9000") is every interface, too.
	_, err = loadConfig(writeConfig(t, `{"api_keys":["real-key","change-me-dev-key"]}`))
	require.Error(t, err)
}

func TestDevKeyAllowedOnLoopback(t *testing.T) {
	c, err := loadConfig(writeConfig(t, `{"listen":"127.0.0.1:9000","api_keys":["change-me-dev-key"]}`))
	require.NoError(t, err)
	assert.Equal(t, []string{"change-me-dev-key"}, c.APIKeys)

	_, err = loadConfig(writeConfig(t, `{"listen":":9000","api_keys":["a-real-key"]}`))
	require.NoError(t, err)
}

func TestExampleConfigLoads(t *testing.T) {
	_, err := loadConfig(filepath.Join("..", "..", "examples", "manager.json"))
	require.NoError(t, err)
}
