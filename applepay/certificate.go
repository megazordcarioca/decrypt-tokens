package applepay

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"

	"time"

	"go.mozilla.org/pkcs7"
)

type ICertificate interface {
	extractCertificates(p7 *pkcs7.PKCS7) (*x509.Certificate, []*x509.Certificate, error)
	validateLeafCertificate(leaf *x509.Certificate) error
	buildIntermediatePool(intermediates []*x509.Certificate) (*x509.CertPool, error)
	addAppleRootCA(appleRootCert string, pool *x509.CertPool) error
	verifyCertificate(leaf *x509.Certificate, roots, intermediates *x509.CertPool, signingTime time.Time) error
	getSigningTime(p7 *pkcs7.PKCS7) (time.Time, error)
}

type CertificateManager struct{}

func NewCertificateManager() *CertificateManager {
	return &CertificateManager{}
}

func (cm *CertificateManager) extractCertificates(p7 *pkcs7.PKCS7) (*x509.Certificate, []*x509.Certificate, error) {
	var leaf *x509.Certificate
	var intermediates []*x509.Certificate

	signer := p7.Signers[0]
	signerIssuer, err := rawToPkixName(signer.IssuerAndSerialNumber.IssuerName)
	if err != nil {
		return nil, nil, err
	}

	for _, cert := range p7.Certificates {
		switch {
		case cert.SerialNumber.Cmp(signer.IssuerAndSerialNumber.SerialNumber) == 0 &&
			cert.Issuer.String() == signerIssuer.String():
			leaf = cert
		default:
			intermediates = append(intermediates, cert)
		}
	}

	if leaf == nil {
		return nil, nil, nil
	}
	return leaf, intermediates, nil
}

func (cm *CertificateManager) validateLeafCertificate(leaf *x509.Certificate) error {
	if !hasOID(leaf, oidAppleLeaf) {
		return nil
	}
	return nil
}

func (cm *CertificateManager) buildIntermediatePool(intermediates []*x509.Certificate) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, cert := range intermediates {
		if hasOID(cert, oidAppleIntermediate) {
			pool.AddCert(cert)
		}
	}
	return pool, nil
}

func (cm *CertificateManager) addAppleRootCA(appleRootCert string, pool *x509.CertPool) error {
	certBytes, err := base64.StdEncoding.DecodeString(appleRootCert)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}

	pool.AddCert(cert)
	return nil
}

func (cm *CertificateManager) verifyCertificate(leaf *x509.Certificate, roots, intermediates *x509.CertPool, signingTime time.Time) error {
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   signingTime,
	}

	if _, err := leaf.Verify(opts); err != nil {
		return err
	}
	return nil
}

func (cm *CertificateManager) getSigningTime(p7 *pkcs7.PKCS7) (time.Time, error) {
	for _, signer := range p7.Signers {
		for _, attr := range signer.AuthenticatedAttributes {
			if attr.Type.Equal(oidSigningTime) {
				var signingTime time.Time
				_, err := asn1.Unmarshal(attr.Value.Bytes, &signingTime)
				if err != nil {
					return time.Time{}, err
				}
				return signingTime, nil
			}
		}
	}
	return time.Time{}, nil
}

func generateSignedDataEcc(ephemeralPublicKey, data, transactionId, applicationData string) ([]byte, error) {
	var signed bytes.Buffer
	ephemeral, err := base64.StdEncoding.DecodeString(ephemeralPublicKey)
	if err != nil {
		return nil, err
	}
	signed.Write(ephemeral)

	dataDecoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	signed.Write(dataDecoded)

	trIDHex, err := hex.DecodeString(transactionId)
	if err != nil {
		return nil, err
	}
	signed.Write(trIDHex)

	appDataHex, err := hex.DecodeString(applicationData)
	if err != nil {
		return nil, err
	}
	if len(appDataHex) > 0 {
		signed.Write(appDataHex)
	}

	return signed.Bytes(), nil
}

func generateSignedDataRsa(wrappedKey, data, transactionId, applicationData string) ([]byte, error) {
	var signed bytes.Buffer
	ephemeral, err := base64.StdEncoding.DecodeString(wrappedKey)
	if err != nil {
		return nil, err
	}
	signed.Write(ephemeral)

	dataDecoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	signed.Write(dataDecoded)

	trIDHex, err := hex.DecodeString(transactionId)
	if err != nil {
		return nil, err
	}
	signed.Write(trIDHex)

	appDataHex, err := hex.DecodeString(applicationData)
	if err != nil {
		return nil, err
	}
	if len(appDataHex) > 0 {
		signed.Write(appDataHex)
	}

	return signed.Bytes(), nil
}

func hasOID(cert *x509.Certificate, targetOID asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(targetOID) {
			return true
		}
	}
	return false
}

func rawToPkixName(raw asn1.RawValue) (pkix.Name, error) {
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw.FullBytes, &rdn); err != nil {
		return pkix.Name{}, err
	}
	var name pkix.Name
	name.FillFromRDNSequence(&rdn)
	return name, nil
}
