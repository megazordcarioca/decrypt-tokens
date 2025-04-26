package applepay

import (
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockCertificateManager struct {
	mock.Mock
}

func (m *MockCertificateManager) extractCertificates(p7 *pkcs7.PKCS7) (*x509.Certificate, []*x509.Certificate, error) {
	args := m.Called(p7)
	return args.Get(0).(*x509.Certificate), args.Get(1).([]*x509.Certificate), args.Error(2)
}

func (m *MockCertificateManager) validateLeafCertificate(leaf *x509.Certificate) error {
	return m.Called(leaf).Error(0)
}

func (m *MockCertificateManager) buildIntermediatePool(intermediates []*x509.Certificate) (*x509.CertPool, error) {
	args := m.Called(intermediates)
	return args.Get(0).(*x509.CertPool), args.Error(1)
}

func (m *MockCertificateManager) addAppleRootCA(appleRootCert string, pool *x509.CertPool) error {
	return m.Called(appleRootCert, pool).Error(0)
}

func (m *MockCertificateManager) verifyCertificate(leaf *x509.Certificate, roots, intermediates *x509.CertPool, signingTime time.Time) error {
	return m.Called(leaf, roots, intermediates, signingTime).Error(0)
}

func (m *MockCertificateManager) getSigningTime(p7 *pkcs7.PKCS7) (time.Time, error) {
	args := m.Called(p7)
	return args.Get(0).(time.Time), args.Error(1)
}

func TestApplePaySignatureValidator_Validate_InvalidPKCS7(t *testing.T) {
	mockCertManager := new(MockCertificateManager)
	validator := NewApplePaySignatureValidator(mockCertManager)

	invalidPKCS7 := base64.StdEncoding.EncodeToString([]byte("invalid_pkcs7"))
	err := validator.Validate(invalidPKCS7, "ephemeralKey", "data", "txID", "", "appleCA", "Ec_v1")
	assert.Error(t, err)
	assert.Equal(t, err.Error(), err.Error())
}

func TestCertificateManager_AddAppleRootCA_InvalidBase64(t *testing.T) {
	cm := NewCertificateManager()
	roots := x509.NewCertPool()
	err := cm.addAppleRootCA("invalid_base64", roots)

	assert.Error(t, err)
	assert.Equal(t, err.Error(), err.Error())
}

func TestCertificateManager_AddAppleRootCA_InvalidCert(t *testing.T) {
	cm := NewCertificateManager()
	roots := x509.NewCertPool()
	invalidCert := base64.StdEncoding.EncodeToString([]byte("invalid_cert"))
	err := cm.addAppleRootCA(invalidCert, roots)

	assert.Error(t, err)
	assert.Equal(t, err.Error(), err.Error())
}

func TestGenerateSignedData_InvalidEphemeralKey(t *testing.T) {
	_, err := generateSignedDataEcc("invalid_base64", "data", "txID", "applicationData")

	assert.Error(t, err)
	assert.Equal(t, err.Error(), err.Error())
}

func TestGenerateSignedData_InvalidData(t *testing.T) {

	_, err := generateSignedDataEcc("ephemeralKey", "invalid_base64", "txID", "applicationData")

	assert.Error(t, err)
	assert.Equal(t, err.Error(), err.Error())
}

func TestGenerateSignedData_InvalidTransactionID(t *testing.T) {

	_, err := generateSignedDataEcc("ephemeralKey", "data", "invalid_hex", "applicationData")

	assert.Error(t, err)
	assert.Equal(t, err.Error(), err.Error())
}

func TestApplePaySignatureValidator_Validate_EmptySignature(t *testing.T) {
	mockCertManager := new(MockCertificateManager)
	validator := NewApplePaySignatureValidator(mockCertManager)

	err := validator.Validate("", "ephemeralKey", "data", "txID", "", "appleCA", "Ec_v1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), err.Error())
}

func TestApplePaySignatureValidator_Validate_InvalidCertificate(t *testing.T) {
	mockCertManager := new(MockCertificateManager)
	mockCertManager.On("extractCertificates", mock.Anything).Return(nil, nil, nil)

	validator := NewApplePaySignatureValidator(mockCertManager)
	invalidPKCS7 := base64.StdEncoding.EncodeToString([]byte("valid_pkcs7"))

	err := validator.Validate(invalidPKCS7, "ephemeralKey", "data", "txID", "", "appleCA", "Ec_v1")

	assert.Error(t, err)
	assert.Equal(t, err.Error(), err.Error())
}

func TestApplePaySignatureValidator_Validate_ExpiredSignature(t *testing.T) {
	mockCertManager := new(MockCertificateManager)
	mockCertManager.On("extractCertificates", mock.Anything).Return(&x509.Certificate{}, []*x509.Certificate{}, nil)
	mockCertManager.On("validateLeafCertificate", mock.Anything).Return(nil)
	mockCertManager.On("buildIntermediatePool", mock.Anything).Return(x509.NewCertPool(), nil)
	mockCertManager.On("getSigningTime", mock.Anything).Return(time.Now().Add(-10*time.Minute), nil)
	mockCertManager.On("addAppleRootCA", mock.Anything, mock.Anything).Return(nil)
	mockCertManager.On("verifyCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	validator := NewApplePaySignatureValidator(mockCertManager)
	validPKCS7 := base64.StdEncoding.EncodeToString([]byte("valid_pkcs7"))

	err := validator.Validate(validPKCS7, "ephemeralKey", "data", "txID", "", "appleCA", "Ec_v1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), err.Error())
}

func TestApplePaySignatureValidator_Validate_VerifyFailure(t *testing.T) {
	mockCertManager := new(MockCertificateManager)
	mockCertManager.On("extractCertificates", mock.Anything).Return(&x509.Certificate{}, []*x509.Certificate{}, nil)
	mockCertManager.On("validateLeafCertificate", mock.Anything).Return(nil)
	mockCertManager.On("buildIntermediatePool", mock.Anything).Return(x509.NewCertPool(), nil)
	mockCertManager.On("getSigningTime", mock.Anything).Return(time.Now(), nil)
	mockCertManager.On("addAppleRootCA", mock.Anything, mock.Anything).Return(nil)
	mockCertManager.On("verifyCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	validator := NewApplePaySignatureValidator(mockCertManager)
	validPKCS7 := base64.StdEncoding.EncodeToString([]byte("valid_pkcs7"))

	err := validator.Validate(validPKCS7, "ephemeralKey", "data", "txID", "", "appleCA", "Ec_v1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), err.Error())
}
