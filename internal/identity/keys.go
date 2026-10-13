package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadSigningKey reads a P-256 private key (SEC 1 "EC PRIVATE KEY", as
// `openssl ecparam -genkey` writes it, or PKCS #8 "PRIVATE KEY") from path.
func LoadSigningKey(path string) (*ecdsa.PrivateKey, error) {
	block, err := readPEM(path)
	if err != nil {
		return nil, err
	}
	key, err := parsePrivate(block)
	if err != nil {
		return nil, fmt.Errorf("signing key %s: %w", path, err)
	}
	return key, nil
}

// LoadVerificationKey reads a P-256 key that is published for verification
// only: a retired signing key file, or a "PUBLIC KEY".
func LoadVerificationKey(path string) (*ecdsa.PublicKey, error) {
	block, err := readPEM(path)
	if err != nil {
		return nil, err
	}
	if block.Type == "PUBLIC KEY" {
		k, perr := x509.ParsePKIXPublicKey(block.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("verification key %s: %w", path, perr)
		}
		pub, ok := k.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, fmt.Errorf("verification key %s: not a P-256 EC key", path)
		}
		return pub, nil
	}
	key, err := parsePrivate(block)
	if err != nil {
		return nil, fmt.Errorf("verification key %s: %w", path, err)
	}
	return &key.PublicKey, nil
}

// readPEM returns the first key block in path, skipping "EC PARAMETERS".
func readPEM(path string) (*pem.Block, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path comes from the operator's config
	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("%s: no PEM key block", path)
		}
		if block.Type != "EC PARAMETERS" {
			return block, nil
		}
	}
}

func parsePrivate(block *pem.Block) (*ecdsa.PrivateKey, error) {
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an EC key")
		}
		key = ec
	default:
		return nil, fmt.Errorf("unsupported PEM block %q", block.Type)
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 key (ES256 needs P-256)")
	}
	return key, nil
}
