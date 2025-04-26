package applepay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"testing"
)

func TestKeyHandler_ECDHAndKDF(t *testing.T) {
	// Gera um par de chaves ECDSA para simular a chave privada do merchant
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Erro ao gerar chave privada: %v", err)
	}

	// Gera um par de chaves ECDSA para simular a chave pública efêmera
	ephemeralPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Erro ao gerar chave efêmera: %v", err)
	}

	// Codifica a chave pública efêmera em ASN.1 DER e depois em base64
	ephemeralPubASN1, err := asn1.Marshal(struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}{
		Algorithm: struct{ Algorithm asn1.ObjectIdentifier }{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
		},
		PublicKey: asn1.BitString{
			Bytes:     elliptic.Marshal(elliptic.P256(), ephemeralPriv.X, ephemeralPriv.Y),
			BitLength: 8 * (len(ephemeralPriv.X.Bytes()) + len(ephemeralPriv.Y.Bytes())),
		},
	})
	if err != nil {
		t.Fatalf("Erro ao codificar chave pública efêmera: %v", err)
	}
	ephemeralPubB64 := base64.StdEncoding.EncodeToString(ephemeralPubASN1)

	handler := NewKeyDerivation()

	// Testa o cálculo do segredo compartilhado
	sharedSecret, err := handler.calculateSharedSecret(priv, ephemeralPubB64)
	if err != nil {
		t.Fatalf("Erro ao calcular segredo compartilhado: %v", err)
	}
	if len(sharedSecret) == 0 {
		t.Error("Segredo compartilhado vazio")
	}

	// Testa a derivação da chave
	partyVInfo := "test-party"
	derivedKey, err := handler.deriveKey(partyVInfo, sharedSecret)
	if err != nil {
		t.Fatalf("Erro ao derivar chave: %v", err)
	}
	if len(derivedKey) == 0 {
		t.Error("Chave derivada vazia")
	}
}
