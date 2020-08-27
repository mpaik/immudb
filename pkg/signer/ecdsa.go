/*
Copyright 2019-2020 vChain, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"math/big"
)

type Signer interface {
	sign(payload []byte) ([]byte, *ecdsa.PublicKey, error)
}

type signer struct {
	rand       io.Reader
	privateKey *ecdsa.PrivateKey
}

type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

// NewSigner returns a signer object. It requires a private key file path. To generate a valid key use openssl tool. Ex: openssl ecparam -name prime256v1 -genkey -noout -out ec.key
func NewSigner(privateKeyPath string) (Signer, error) {
	privateKeyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil {
		return nil, errors.New("no key found in provided file")
	}
	privateKey, err := x509.ParseECPrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return signer{rand: rand.Reader, privateKey: privateKey}, nil
}

// sign sign a payload and returns asn1 marshal byte sequence
func (sig signer) sign(payload []byte) ([]byte, *ecdsa.PublicKey, error) {
	r, s, err := ecdsa.Sign(sig.rand, sig.privateKey, payload)
	if err != nil {
		return nil, nil, err
	}
	sigToMarshal := ecdsaSignature{R: r, S: s}
	m, _ := asn1.Marshal(sigToMarshal)
	return m, &sig.privateKey.PublicKey, nil
}

// verify verifies a signed payload
func Verify(payload []byte, signature []byte, publicKey *ecdsa.PublicKey) (bool, error) {
	es := ecdsaSignature{}
	if _, err := asn1.Unmarshal(signature, &es); err != nil {
		return false, err
	}
	return ecdsa.Verify(publicKey, payload, es.R, es.S), nil
}
