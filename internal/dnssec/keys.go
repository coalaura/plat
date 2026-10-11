package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/miekg/dns"
)

const MLDSA44 uint8 = 18

func SupportedAlgorithm(algorithm uint8) bool {
	switch algorithm {
	case dns.RSASHA256, dns.RSASHA512, dns.ECDSAP256SHA256, dns.ECDSAP384SHA384, dns.ED25519, dns.ED448, MLDSA44:
		return true
	}

	return false
}

func GenerateKey(key *dns.DNSKEY) (crypto.Signer, string, error) {
	if key.Algorithm == dns.ED448 {
		public, private, err := ed448.GenerateKey(nil)
		if err != nil {
			return nil, "", err
		}

		key.PublicKey = base64.StdEncoding.EncodeToString(public)

		encoded := "Private-key-format: v1.3\nAlgorithm: 16 (ED448)\nPrivateKey: " + base64.StdEncoding.EncodeToString(private[:ed448.SeedSize]) + "\n"

		return private, encoded, nil
	}

	if key.Algorithm == MLDSA44 {
		private, err := mldsa.GenerateKey(mldsa.MLDSA44())
		if err != nil {
			return nil, "", err
		}

		key.PublicKey = base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())

		encoded := "Private-key-format: v1.3\nAlgorithm: 18 (MLDSA44)\nPrivateKey: " + base64.StdEncoding.EncodeToString(private.Bytes()) + "\n"

		return private, encoded, nil
	}

	bits := 256

	switch key.Algorithm {
	case dns.RSASHA256, dns.RSASHA512:
		bits = 3072
	case dns.ECDSAP384SHA384:
		bits = 384
	case dns.ECDSAP256SHA256, dns.ED25519:
	default:
		return nil, "", errors.New("unsupported DNSSEC algorithm")
	}

	private, err := key.Generate(bits)
	if err != nil {
		return nil, "", err
	}

	return private.(crypto.Signer), key.PrivateKeyString(private), nil
}

func LoadKey(key *dns.DNSKEY, encoded string) (crypto.Signer, error) {
	if !SupportedAlgorithm(key.Algorithm) {
		return nil, errors.New("unsupported DNSSEC algorithm")
	}

	seed, err := privateKeySeed(key.Algorithm, encoded)
	if err != nil {
		return nil, err
	}

	if key.Algorithm == MLDSA44 {
		return loadMLDSAKey(key, seed)
	}

	if key.Algorithm == dns.ED448 {
		return loadEd448Key(key, seed)
	}

	private, err := key.NewPrivateKey(encoded)
	if err != nil {
		return nil, err
	}

	// The BIND parser attaches the supplied DNSKEY to RSA/ECDSA private keys
	// without checking that the private material actually produces that key.
	switch signer := private.(type) {
	case *rsa.PrivateKey:
		if signer.D == nil || len(signer.Primes) != 2 || signer.Primes[0] == nil || signer.Primes[1] == nil {
			return nil, errors.New("invalid RSA private key")
		}

		err = signer.Validate()
		if err != nil {
			return nil, err
		}

		return signer, nil
	case *ecdsa.PrivateKey:
		if signer.D.Sign() <= 0 || signer.D.Cmp(signer.Params().N) >= 0 {
			return nil, errors.New("invalid ECDSA private key")
		}

		publicX, publicY := signer.Curve.ScalarBaseMult(signer.D.Bytes())
		if publicX.Cmp(signer.X) != 0 || publicY.Cmp(signer.Y) != 0 {
			return nil, errors.New("private key does not match DNSKEY")
		}

		return signer, nil
	case ed25519.PrivateKey:
		if len(signer) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid Ed25519 private key")
		}

		// NewPrivateKey derives the public-key suffix from the saved seed.
		if base64.StdEncoding.EncodeToString(signer[ed25519.SeedSize:]) != key.PublicKey {
			return nil, errors.New("private key does not match DNSKEY")
		}

		return signer, nil
	default:
		return nil, errors.New("invalid DNSSEC private key")
	}
}

func loadEd448Key(key *dns.DNSKEY, seed string) (crypto.Signer, error) {
	decoded, err := base64.StdEncoding.DecodeString(seed)
	if err != nil {
		return nil, err
	}

	if len(decoded) != ed448.SeedSize {
		return nil, errors.New("invalid Ed448 private key")
	}

	private := ed448.NewKeyFromSeed(decoded)
	if base64.StdEncoding.EncodeToString(private[ed448.SeedSize:]) != key.PublicKey {
		return nil, errors.New("private key does not match DNSKEY")
	}

	return private, nil
}

func loadMLDSAKey(key *dns.DNSKEY, seed string) (crypto.Signer, error) {
	decoded, err := base64.StdEncoding.DecodeString(seed)
	if err != nil {
		return nil, err
	}

	private, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), decoded)
	if err != nil {
		return nil, err
	}

	if base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()) != key.PublicKey {
		return nil, errors.New("private key does not match DNSKEY")
	}

	return private, nil
}

func privateKeySeed(algorithm uint8, encoded string) (string, error) {
	var format, algorithmNumber, seed string

	for line := range strings.SplitSeq(encoded, "\n") {
		field, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}

		value = strings.TrimSpace(value)

		switch strings.ToLower(strings.TrimSpace(field)) {
		case "private-key-format":
			format = value
		case "algorithm":
			algorithmNumber, _, _ = strings.Cut(value, " ")
		case "privatekey":
			seed = value
		}
	}

	if (format != "v1.2" && format != "v1.3") || algorithmNumber != strconv.Itoa(int(algorithm)) {
		return "", errors.New("invalid private key format or algorithm")
	}

	return seed, nil
}
