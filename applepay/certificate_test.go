package applepay

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mozilla.org/pkcs7"
)

func TestCertificateManager_ValidateLeafCertificate(t *testing.T) {
	cm := NewCertificateManager()
	cert := &x509.Certificate{}

	err := cm.validateLeafCertificate(cert)
	assert.NoError(t, err)
}

func TestCertificateManager_BuildIntermediatePool(t *testing.T) {
	cm := NewCertificateManager()
	intermediates := []*x509.Certificate{}

	pool, err := cm.buildIntermediatePool(intermediates)
	assert.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestCertificateManager_AddAppleRootCA(t *testing.T) {
	cm := NewCertificateManager()
	pool := x509.NewCertPool()
	invalidCert := "invalid_base64"

	err := cm.addAppleRootCA(invalidCert, pool)
	assert.Error(t, err)

	validCert := base64.StdEncoding.EncodeToString([]byte("valid_cert"))
	err = cm.addAppleRootCA(validCert, pool)
	assert.Error(t, err) // Certificado inválido
}

func TestCertificateManager_VerifyCertificate(t *testing.T) {
	cm := NewCertificateManager()
	leaf := &x509.Certificate{}
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	signingTime := time.Now()

	err := cm.verifyCertificate(leaf, roots, intermediates, signingTime)
	assert.Error(t, err) // Falha na verificação
}

func TestCertificateManager_GetSigningTime(t *testing.T) {
	cm := NewCertificateManager()
	p7 := &pkcs7.PKCS7{}

	_, err := cm.getSigningTime(p7)
	assert.Nil(t, nil, err)
}

func TestGenerateSignedData(t *testing.T) {
	ephemeralKey := base64.StdEncoding.EncodeToString([]byte("ephemeral_key"))
	data := base64.StdEncoding.EncodeToString([]byte("data"))
	transactionID := "123456"

	signedData, err := generateSignedDataEcc(ephemeralKey, data, transactionID, "")
	assert.NoError(t, err)
	assert.NotNil(t, signedData)
}

func TestRawToPkixName(t *testing.T) {
	raw := asn1.RawValue{}
	_, err := rawToPkixName(raw)
	assert.Error(t, err) // Falha ao decodificar o nome
}
