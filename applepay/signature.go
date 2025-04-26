package applepay

import (
	"crypto/x509"
	"encoding/base64"

	"errors"
	"time"

	"go.mozilla.org/pkcs7"
)

type ISignature interface {
	Validate(signature, key, data, transactionId, applicationData, appleCaBase64, version string) error
}

type SignatureValidator struct {
	certificateManager ICertificate
}

func NewApplePaySignatureValidator(certificateManager ICertificate) *SignatureValidator {
	return &SignatureValidator{
		certificateManager: certificateManager,
	}
}

func (v *SignatureValidator) Validate(signature, key, data, transactionId, applicationData, appleCaBase64, version string) error {
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	p7, err := pkcs7.Parse(signatureBytes)
	if err != nil {
		return err
	}

	leaf, intermediates, err := v.certificateManager.extractCertificates(p7)
	if err != nil {
		return err
	}

	if err := v.certificateManager.validateLeafCertificate(leaf); err != nil {
		return err
	}

	intermediatePool, err := v.certificateManager.buildIntermediatePool(intermediates)
	if err != nil {
		return err
	}

	signingTime, err := v.certificateManager.getSigningTime(p7)
	if err != nil {
		return err
	}

	roots := x509.NewCertPool()
	if err := v.certificateManager.addAppleRootCA(appleCaBase64, roots); err != nil {
		return err
	}

	if err := v.certificateManager.verifyCertificate(leaf, roots, intermediatePool, signingTime); err != nil {
		return err
	}

	var signed []byte
	if version != "Ec_v1" {
		signed, err = generateSignedDataRsa(key, data, transactionId, applicationData)
		if err != nil {
			return err
		}
	} else {
		signed, err = generateSignedDataEcc(key, data, transactionId, applicationData)
		if err != nil {
			return err
		}
	}
	p7.Content = signed

	if err := p7.Verify(); err != nil {
		return err
	}

	if time.Since(signingTime) > 5*time.Minute {
		return errors.New(PayloadExceededTimeMessage)
	}
	return nil
}
