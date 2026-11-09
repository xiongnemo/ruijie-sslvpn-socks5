// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlstransport

import (
	"crypto/sha512"
	"errors"
	"hash"
	"sync/atomic"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

const gatewayCipherSuiteID dtls.CipherSuiteID = 0xc028

var errCipherNotInitialized = errors.New("DTLS AES-256-CBC-SHA384 cipher is not initialized")

// gatewayCipherSuites supplies the RFC 5289 suite selected by the real gateway.
// Each call returns new per-connection state. Pion's supported public CBC and PRF
// implementations perform all record cryptography and authentication checks.
func gatewayCipherSuites() []dtls.CipherSuite {
	return []dtls.CipherSuite{&ecdheRSAWithAES256CBCSHA384{}}
}

// Adapted from Pion's TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA suite. This suite
// changes authentication to RSA, and both the record MAC and TLS 1.2 PRF to
// SHA-384; AES-256 and the 16-byte explicit record IV remain unchanged.
type ecdheRSAWithAES256CBCSHA384 struct {
	cbc atomic.Pointer[ciphersuite.CBC]
}

var _ dtls.CipherSuite = (*ecdheRSAWithAES256CBCSHA384)(nil)

func (*ecdheRSAWithAES256CBCSHA384) ID() dtls.CipherSuiteID { return gatewayCipherSuiteID }
func (*ecdheRSAWithAES256CBCSHA384) String() string {
	return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
}
func (*ecdheRSAWithAES256CBCSHA384) CertificateType() clientcertificate.Type {
	return clientcertificate.RSASign
}
func (*ecdheRSAWithAES256CBCSHA384) KeyExchangeAlgorithm() dtls.CipherSuiteKeyExchangeAlgorithm {
	return dtls.CipherSuiteKeyExchangeAlgorithmEcdhe
}
func (*ecdheRSAWithAES256CBCSHA384) AuthenticationType() dtls.CipherSuiteAuthenticationType {
	return dtls.CipherSuiteAuthenticationTypeCertificate
}
func (*ecdheRSAWithAES256CBCSHA384) ECC() bool { return true }
func (*ecdheRSAWithAES256CBCSHA384) HashFunc() func() hash.Hash {
	return sha512.New384
}
func (c *ecdheRSAWithAES256CBCSHA384) IsInitialized() bool { return c.cbc.Load() != nil }

func (c *ecdheRSAWithAES256CBCSHA384) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	keys, err := prf.GenerateEncryptionKeys(masterSecret, clientRandom, serverRandom, 48, 32, 16, c.HashFunc())
	if err != nil {
		return err
	}
	var recordCipher *ciphersuite.CBC
	if isClient {
		recordCipher, err = ciphersuite.NewCBC(
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey,
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey, sha512.New384)
	} else {
		recordCipher, err = ciphersuite.NewCBC(
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey,
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey, sha512.New384)
	}
	if err != nil {
		return err
	}
	c.cbc.Store(recordCipher)
	return nil
}

func (c *ecdheRSAWithAES256CBCSHA384) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	cbc := c.cbc.Load()
	if cbc == nil {
		return nil, errCipherNotInitialized
	}
	return cbc.Encrypt(pkt, raw)
}

func (c *ecdheRSAWithAES256CBCSHA384) Decrypt(header recordlayer.Header, raw []byte) ([]byte, error) {
	cbc := c.cbc.Load()
	if cbc == nil {
		return nil, errCipherNotInitialized
	}
	return cbc.Decrypt(header, raw)
}
