package applepay

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"encoding/base64"
)

type Cipher interface {
	Decrypt(encryptedData string) ([]byte, error)
}

type applePayCipher struct {
	symmetricKey []byte
}

func NewApplePayCipher(ephemeralPublicKey string, privateKey *ecdsa.PrivateKey, merchantId string) (Cipher, error) {
	keyExchange := &KeyDerivation{}
	sharedSecret, err := keyExchange.calculateSharedSecret(privateKey, ephemeralPublicKey)
	if err != nil {
		return nil, err
	}

	keyDerivation := &KeyDerivation{}
	symmetricKey, err := keyDerivation.deriveKey(merchantId, sharedSecret)
	if err != nil {
		return nil, err
	}

	return &applePayCipher{
		symmetricKey: symmetricKey,
	}, nil
}

func (a *applePayCipher) Decrypt(data string) ([]byte, error) {

	cipherTextBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(a.symmetricKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceSize)
	return aesGCM.Open(nil, nonce, cipherTextBytes, nil)
}

func (a *applePayCipher) SetKey(key []byte) {

	a.symmetricKey = key
}
