package serialize

import (
	"encoding/hex"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)


func isOddFp(x *fp.Element) bool {
	return x.BigInt(big.NewInt(0)).Bit(0) == 1
}

/*
	func isOddHexString(x string) bool {
		cc, _ := new(big.Int).SetString(x, 16)
		log.Printf("y: %s, %d\n", cc.String(), cc.Bit(0))
		return cc.Bit(0) == 1
	}
*/
func ReverseHexString(hexStr string) string {
	reversed := make([]byte, len(hexStr))
	for i := 0; i < len(hexStr); i += 2 {
		reversed[i] = hexStr[len(hexStr)-i-2]
		reversed[i+1] = hexStr[len(hexStr)-i-1]
	}
	return string(reversed)

}
func SerializeG1(g1 *ArkHex2ProofG1) (string, error) {
	cc, _ := new(big.Int).SetString(g1.Y, 16)
	var elementY fp.Element
	elementY.SetString(cc.String())
	if isOddFp(&elementY) {
		xBytes, err := hex.DecodeString(g1.X)
		if err != nil {
			return "", err
		}
		xBytes[0] |= 0x80
		return ReverseHexString(hex.EncodeToString(xBytes)), nil
	} else {
		return ReverseHexString(g1.X), nil
	}

}

func SerializeG2(g2 *ArkHex2ProofG2) (string, error) {
	cc, _ := new(big.Int).SetString(g2.Y.A0, 16)
	var elementY fp.Element
	elementY.SetString(cc.String())
	if isOddFp(&elementY) {
		xBytes, err := hex.DecodeString(g2.X.A1)
		if err != nil {
			return "", err
		}
		xBytes[0] |= 0x80
		return ReverseHexString(g2.X.A0) + ReverseHexString(hex.EncodeToString(xBytes)), nil
	} else {
		return ReverseHexString(g2.X.A0) + ReverseHexString(g2.X.A1), nil
	}

}
