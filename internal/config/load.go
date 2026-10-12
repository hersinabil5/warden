package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Load reads and validates the config file at path. getenv resolves secrets
// referenced by environment variable name (main passes os.Getenv).
func Load(path string, getenv func(string) string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is the operator's -config flag
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	cfg, err := Parse(data, getenv)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes and validates a config. Decoding is strict: unknown fields,
// duplicate keys, wrong types, and extra YAML documents are errors. It returns
// either a fully valid, normalized config or nil and every problem found.
func Parse(data []byte, getenv func(string) string) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config is empty")
		}
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("config contains multiple YAML documents; expected exactly one")
	}

	if err := cfg.validate(getenv); err != nil {
		return nil, err
	}
	return &cfg, nil
}
