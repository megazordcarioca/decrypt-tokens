# Apple Pay Module

A Go module for decrypting Apple Pay tokens using merchant private keys and certificates, implementing Apple's Payment Token format specification.

## 📚 Official References
- [Apple Payment Token Format Reference](https://developer.apple.com/documentation/passkit/payment-token-format-reference)
- [Restoring the symmetric key](https://developer.apple.com/documentation/PassKit/restoring-the-symmetric-key)
- [NIST SP 800-56A, section 5.8.1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf)

## 💻 Usage

### Prerequisites
- Private key in PKCS#8 format (as specified in Apple's cryptography requirements)
- Merchant certificate in X.509 format from Apple Pay Merchant ID
- Apple Pay payment token data following [Payment Token format](https://developer.apple.com/documentation/passkit/payment-token-format-reference)

### Basic Implementation

```go
import (
  "github.com/megazordcarioca/decrypt-tokens/applepay"
  "context"
  "fmt"
)

func main() {
    // Initialize with your key and certificate paths
    privateKeyPath := "./privateKey.pem"  // PKCS#8 format as per Apple requirements
    certificatePath := "./cert.pem"       // X.509 certificate from Apple Pay Merchant ID

    // Load cryptographic materials
    privateKey, err := loadPrivateKey(privateKeyPath)
    if err != nil {
        panic(fmt.Sprintf("Failed to load private key: %v", err))
    }

    certificate, err := loadCertificate(certificatePath)
    if err != nil {
        panic(fmt.Sprintf("Failed to load certificate: %v", err))
    }

    // Create decryptor instance
    decryptor := applepay.NewApplePayHandler(privateKey, certificate)

    // Payment token data structure as defined in:
    // https://developer.apple.com/documentation/passkit/payment-token-format-reference
    paymentData := "base64EncryptedData"          // PKPaymentToken.paymentData
    paymentHeader := "paymentHeader"              // PKPaymentToken.header
    ephemeralPublicKey := "ephemeralPublicKey"    // PKPaymentToken.header.ephemeralPublicKey
    transactionId := "transaction123"             // PKPaymentToken.header.transactionId

    // Decrypt the token following Apple's cryptography specification
    result, err := decryptor.Decrypt(
        context.Background(),
        paymentData,
        paymentHeader,
        ephemeralPublicKey,
        transactionId,
    )

    if err != nil {
        fmt.Println("Decryption failed:", err.Error())
        return
    }

    fmt.Println("Successfully decrypted:", result)
}
```
### 🔧 Configuration
Required Parameters
All parameters follow Apple's Payment Token format specification:

| Parameter           | Apple Pay Equivalent             | Description                                                        |
|---------------------|----------------------------------|--------------------------------------------------------------------|
| ```privateKey```          | Merchant Private Key             | PKCS#8 formatted key as specified in Cryptographic Details         |
| ```certificate```         | Merchant Certificate             | X.509 certificate from Apple Pay Merchant ID                          |
| ```paymentData```         | PKPaymentToken.paymentData       | Base64-encoded encrypted payment data containing sensitive payment information |
| ```paymentHeader```       | PKPaymentToken.header            | Contains metadata needed for decryption                            |
| ```ephemeralPublicKey```  | header.ephemeralPublicKey        | Elliptic curve public key used for ECIES (Ephemeral)               |
| ```transactionId```       | header.transactionId             | Unique identifier for the payment transaction                      |

### 🚨 Error Handling

The module implements error handling according to Apple's specifications:

Invalid cryptographic materials: Returns error if keys don't meet Apple's requirements

Malformed input data: Validates token structure against Payment Token format

Decryption failures: Handles errors during the ECC decryption process

Validation errors: Verifies token integrity and expiration

### 🔐 Security Considerations

As specified in Apple's documentation:

Key Management:

Private keys must be stored securely (HSM recommended)

Rotate keys periodically as per Apple's guidelines

Token Handling:

Process tokens immediately (they have limited validity)

Never store decrypted payment data unnecessarily

Transport Security:

Always use TLS 1.2+ when transmitting payment tokens

Validate merchant certificates chain to Apple's root CA

### 📝 Additional Notes

The module implements the full decryption flow specified in Apple's documentation:

Key derivation using ECDH

Symmetric decryption using AES-GCM

Data validation and integrity checking

For test environments, use Apple's test cards

Production implementation requires proper Apple Pay merchant certification

### 🆘 Troubleshooting

Common issues and solutions:

| Issue                | Solution                                                        |
|----------------------|-----------------------------------------------------------------|
| ```Invalid key format```   | Ensure private key is PKCS#8 and certificate is X.509           |
| ```Decryption failures```  | Verify all token components match Apple's format                |
| ```Expired tokens```       | Tokens are valid for limited time - process immediately         |
| ```Certificate issues```   | Re-download from Apple Merchant portal if expired               |