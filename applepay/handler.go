package applepay

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
)

// HandlerInterface define o contrato para o handler Apple Pay.
type HandlerInterface interface {
	Validate(ctx context.Context, data, signature, key, transactionId, applicationData, appleCaBase64, version string) error
	Decrypt(ctx context.Context, data, publicKeyHash, key, version string) ([]byte, error)
}

// Handler implementa HandlerInterface.
type Handler struct {
	eccDecryptor       EccDecryptor
	signatureValidator ISignature
}

// NewHandler cria uma nova instância de Handler com as dependências fornecidas.
func NewHandler(eccDecryptor EccDecryptor, signatureValidator ISignature) *Handler {
	return &Handler{
		eccDecryptor:       eccDecryptor,
		signatureValidator: signatureValidator,
	}
}

// Validate valida a assinatura do Apple Pay.
func (h *Handler) Validate(ctx context.Context, data, signature, key, transactionId, applicationData, appleCaBase64, version string) error {
	return h.signatureValidator.Validate(signature, key, data, transactionId, applicationData, appleCaBase64, version)
}

// Decrypt realiza a descriptografia do payload do Apple Pay.
func (h *Handler) Decrypt(ctx context.Context, data, publicKeyHash, key, version string) ([]byte, error) {

	switch version {
	case "EC_v1":
		return h.eccDecryptor.DecryptPayload(publicKeyHash, key, data)
	default:
		return nil, fmt.Errorf(IncorrectProtocolVersionMessage+"%s", version)
	}
}

// NewApplePayHandler cria e configura um Handler completo para Apple Pay.
func NewApplePayHandler(privateKey *ecdsa.PrivateKey, certificate *x509.Certificate) HandlerInterface {
	return NewHandler(
		NewApplePayDecryptor(privateKey, certificate),
		NewApplePaySignatureValidator(NewCertificateManager()),
	)
}
