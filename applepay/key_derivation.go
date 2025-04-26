package applepay

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
)

type KeyDerivation struct {
	curve ecdh.Curve
}

func NewKeyDerivation() *KeyDerivation {
	return &KeyDerivation{
		curve: ecdh.P256(),
	}
}

// Calcula o segredo compartilhado ECDH
func (k *KeyDerivation) calculateSharedSecret(privateKey *ecdsa.PrivateKey, ephemeralPublicKey string) ([]byte, error) {
	ephemeralPublicKeyDER, err := base64.StdEncoding.DecodeString(ephemeralPublicKey)
	if err != nil {
		return nil, err
	}

	var parsedKey struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(ephemeralPublicKeyDER, &parsedKey); err != nil {
		return nil, err
	}

	ecdhPub, err := k.curve.NewPublicKey(parsedKey.PublicKey.Bytes)
	if err != nil {
		return nil, err
	}

	privateKeyBytes := privateKey.D.FillBytes(make([]byte, 32))
	calculatedSharedSecret, err := k.curve.NewPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	return calculatedSharedSecret.ECDH(ecdhPub)
}

// Deriva a chave usando concatKDF
func (k *KeyDerivation) deriveKey(partyVInfo string, sharedSecret []byte) ([]byte, error) {
	sumPartyVInfo := sha256.Sum256([]byte(partyVInfo))

	otherInfo := make([]byte, 0)
	otherInfo = append(otherInfo, KdfAlgorithm...)
	otherInfo = append(otherInfo, KdfPartyU...)
	otherInfo = append(otherInfo, sumPartyVInfo[:]...)

	return concatKDFCore(sharedSecret, otherInfo, KeyLength), nil
}

func concatKDFCore(z []byte, otherInfo []byte, keyLen int) []byte {
	hashSize := sha256.Size
	reps := (keyLen + hashSize - 1) / hashSize
	result := make([]byte, 0, reps*hashSize)

	for i := 1; i <= reps; i++ {
		counter := make([]byte, 4)
		binary.BigEndian.PutUint32(counter, uint32(i))
		hash := sha256.New()
		hash.Write(counter)
		hash.Write(z)
		hash.Write(otherInfo)
		result = hash.Sum(result)
	}

	return result[:keyLen]
}
