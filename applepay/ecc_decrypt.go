package applepay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

type EccDecryptor interface {
	DecryptPayload(publicKeyHash, ephemeralPublicKey, data string) ([]byte, error)
}

type EccApplePayDecryptor struct {
	privateKey   *ecdsa.PrivateKey
	merchantCert *x509.Certificate
	keyHandler   *KeyDerivation
	cipher       Cipher
	symmetricKey []byte
}

// NewApplePayDecryptor cria uma nova instância de ApplePayDecrypt
func NewApplePayDecryptor(privateKey *ecdsa.PrivateKey, merchantCert *x509.Certificate) *EccApplePayDecryptor {
	return &EccApplePayDecryptor{
		privateKey:   privateKey,
		merchantCert: merchantCert,
		keyHandler:   NewKeyDerivation(),
		cipher:       &applePayCipher{},
	}
}

func (d *EccApplePayDecryptor) DecryptPayload(publicKeyHash, ephemeralPublicKey, data string) ([]byte, error) {
	if err := d.validatePublicKeyHash(publicKeyHash); err != nil {
		return nil, err
	}

	if err := d.generateSymmetricKey(ephemeralPublicKey); err != nil {
		return nil, err
	}

	d.configureCipher()

	plaintext, err := d.cipher.Decrypt(data)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

func (d *EccApplePayDecryptor) validatePublicKeyHash(publicKeyHash string) error {
	pubKey, ok := d.merchantCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil
	}

	pubKeyDer, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return err
	}

	decodedHash, err := base64.StdEncoding.DecodeString(publicKeyHash)
	if err != nil {
		return err
	}

	computedHash := sha256.Sum256(pubKeyDer)
	if !bytes.Equal(computedHash[:], decodedHash) {
		return nil
	}

	return nil
}

func (d *EccApplePayDecryptor) generateSymmetricKey(ephemeralPublicKey string) error {
	secret, err := d.keyHandler.calculateSharedSecret(d.privateKey, ephemeralPublicKey)
	if err != nil {
		return err
	}

	merchantID, err := d.getMerchantId()
	if err != nil {
		return err
	}

	symKey, err := d.keyHandler.deriveKey(merchantID, secret)
	if err != nil {
		return err
	}

	d.symmetricKey = symKey
	return nil
}

func (d *EccApplePayDecryptor) configureCipher() {
	if cipher, ok := d.cipher.(*applePayCipher); ok {
		cipher.SetKey(d.symmetricKey)
	}
}

func (d *EccApplePayDecryptor) getMerchantId() (string, error) {
	commonName := d.merchantCert.Subject.CommonName
	if commonName == "" {
		return "", nil
	}
	return extractMerchantId(commonName), nil
}

// extractMerchantId extrai o ID do merchant do CommonName
func extractMerchantId(commonName string) string {
	parts := strings.SplitN(commonName, ":", 2)
	if len(parts) > 1 {
		return parts[1]
	}
	return commonName
}
