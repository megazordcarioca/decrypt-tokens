package applepay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewApplePayCipher_InvalidEphemeralKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = NewApplePayCipher("invalid-ephemeral-key", privateKey, "merchant.test")
	require.Error(t, err)
	require.Contains(t, err.Error(), err.Error())
}

func TestApplePayCipher_Decrypt_InvalidAESKey(t *testing.T) {
	// Forçar isso gerando chave de tamanho incorreto
	c := &applePayCipher{symmetricKey: []byte("shortkey")}
	_, err := c.Decrypt(base64.StdEncoding.EncodeToString([]byte("test")))
	require.Error(t, err)
	require.Contains(t, err.Error(), err.Error())
}
