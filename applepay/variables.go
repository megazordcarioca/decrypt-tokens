package applepay

import "encoding/asn1"

var (
	oidAppleLeaf         = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 29}
	oidAppleIntermediate = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 14}
	oidSigningTime       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)
