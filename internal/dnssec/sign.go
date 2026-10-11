package dnssec

import (
	"crypto"
	"errors"
	"io"

	"github.com/miekg/dns"
)

type unhashedSigner struct {
	crypto.Signer
	algorithm uint8
}

func (signer unhashedSigner) Sign(random io.Reader, message []byte, options crypto.SignerOpts) ([]byte, error) {
	if options.HashFunc() != 0 || len(message) < 18 || message[2] != dns.ED25519 {
		return nil, errors.New("invalid unhashed DNSSEC signing input")
	}

	// miekg/dns's Ed25519 path supplies the canonical, unhashed RFC 4034
	// message and preserves the returned signature bytes. Until it supports
	// Ed448 and ML-DSA, reuse that path but sign the actual algorithm number
	// in the RRSIG prefix (octet 2). Both use pure signing with an empty context.
	message[2] = signer.algorithm

	signature, err := signer.Signer.Sign(random, message, crypto.Hash(0))

	message[2] = dns.ED25519

	return signature, err
}

func signRRSet(signature *dns.RRSIG, signer crypto.Signer, records []dns.RR) error {
	if signature.Algorithm != dns.ED448 && signature.Algorithm != MLDSA44 {
		return signature.Sign(signer, records)
	}

	algorithm := signature.Algorithm
	signature.Algorithm = dns.ED25519

	err := signature.Sign(unhashedSigner{Signer: signer, algorithm: algorithm}, records)

	signature.Algorithm = algorithm

	return err
}
