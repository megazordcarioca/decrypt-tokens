package applepay

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func generateTestKeys() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "merchant.com:1234567890",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, cert, nil
}

func TestDecryptPayload_InvalidPublicKeyHash(t *testing.T) {
	privateKey, cert, err := generateTestKeys()
	assert.NoError(t, err)

	publicKeyHash := "invalid_hash"
	ephemeralPublicKey := base64.StdEncoding.EncodeToString([]byte("invalid_ephemeral_key"))
	data := base64.StdEncoding.EncodeToString([]byte("invalid_data"))

	decryptor := NewApplePayDecryptor(privateKey, cert)
	_, err = decryptor.DecryptPayload(publicKeyHash, ephemeralPublicKey, data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), err.Error())
}

func TestExtractMerchantId(t *testing.T) {
	commonName := "merchant.com:1234567890"
	merchantID := extractMerchantId(commonName)
	assert.Equal(t, "1234567890", merchantID)

	commonName = "merchant.com"
	merchantID = extractMerchantId(commonName)
	assert.Equal(t, "merchant.com", merchantID)
}

func TestSharedSecret_Generation(t *testing.T) {
	privateKey, _, err := generateTestKeys()
	assert.NoError(t, err)

	ephemeralPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	ephemeralPubBytes, err := x509.MarshalPKIXPublicKey(&ephemeralPriv.PublicKey)
	assert.NoError(t, err)
	ephemeralPublicKey := base64.StdEncoding.EncodeToString(ephemeralPubBytes)

	keyExchange := &KeyDerivation{curve: ecdh.P256()}
	secret, err := keyExchange.calculateSharedSecret(privateKey, ephemeralPublicKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
}

func TestKeyDerivation(t *testing.T) {
	merchantID := "1234567890"
	sharedSecret := []byte("test_secret")

	keyDerivation := &KeyDerivation{}
	key, err := keyDerivation.deriveKey(merchantID, sharedSecret)
	assert.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestDecryptPayload_PublicKeyHashMismatch(t *testing.T) {
	privateKey, cert, err := generateTestKeys()
	assert.NoError(t, err)

	publicKeyHash := base64.StdEncoding.EncodeToString([]byte("invalid_hash"))
	ephemeralPublicKey := base64.StdEncoding.EncodeToString([]byte("valid_ephemeral_key"))
	data := base64.StdEncoding.EncodeToString([]byte("valid_data"))

	decryptor := NewApplePayDecryptor(privateKey, cert)
	_, err = decryptor.DecryptPayload(publicKeyHash, ephemeralPublicKey, data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), err.Error())
}

type MockCipher struct {
	DecryptFunc func(key []byte, data string) ([]byte, error)
}

func (m *MockCipher) Decrypt(data string) ([]byte, error) {
	return m.DecryptFunc(nil, data)
}
