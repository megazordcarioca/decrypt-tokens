package applepay

const (
	NonceSize                       = 16
	KdfAlgorithm                    = "\x0Did-aes256-GCM"
	KdfPartyU                       = "Apple"
	KeyLength                       = 32
	PayloadExceededTimeMessage      = "signature is older than 5 minutes"
	IncorrectProtocolVersionMessage = "unsupported encrypotion version, got:"
)
