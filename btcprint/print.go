package btcprint

import (
	"doge-covenant/serialize"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

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
func reverseHexString(hexStr string) string {
	reversed := make([]byte, len(hexStr))
	for i := 0; i < len(hexStr); i += 2 {
		reversed[i] = hexStr[len(hexStr)-i-2]
		reversed[i+1] = hexStr[len(hexStr)-i-1]
	}
	return string(reversed)

}
func serializeG1(g1 *serialize.ArkHex2ProofG1) (string, error) {
	cc, _ := new(big.Int).SetString(g1.Y, 16)
	var elementY fp.Element
	elementY.SetString(cc.String())
	if isOddFp(&elementY) {
		xBytes, err := hex.DecodeString(g1.X)
		if err != nil {
			return "", err
		}
		xBytes[0] |= 0x80
		return reverseHexString(hex.EncodeToString(xBytes)), nil
	} else {
		return reverseHexString(g1.X), nil
	}

}

func serializeG2(g2 *serialize.ArkHex2ProofG2) (string, error) {
	cc, _ := new(big.Int).SetString(g2.Y.A0, 16)
	var elementY fp.Element
	elementY.SetString(cc.String())
	if isOddFp(&elementY) {
		xBytes, err := hex.DecodeString(g2.X.A1)
		if err != nil {
			return "", err
		}
		xBytes[0] |= 0x80
		return reverseHexString(g2.X.A0) + reverseHexString(hex.EncodeToString(xBytes)), nil
	} else {
		return reverseHexString(g2.X.A0) + reverseHexString(g2.X.A1), nil
	}

}

func PrintArkHex2VK(vk *serialize.ArkHex2VK) (string, error) {
	var sb strings.Builder
	piAlphaG1, err := serializeG1(&vk.AlphaG1)
	if err != nil {
		return "", err
	}
	sb.WriteString(piAlphaG1)

	for _, g1 := range vk.G1K {
		piG1, err := serializeG1(&g1)
		if err != nil {
			return "", err
		}

		sb.WriteString(piG1)
	}
	bg2, err := serializeG2(&vk.BetaG2)
	if err != nil {
		return "", err
	}
	dg2, err := serializeG2(&vk.DeltaG2)
	if err != nil {
		return "", err
	}
	gg2, err := serializeG2(&vk.GammaG2)
	if err != nil {
		return "", err
	}

	sb.WriteString(bg2)
	sb.WriteString(dg2)
	sb.WriteString(gg2)

	combinedHex := sb.String()
	sb.Reset()

	for i := 0; i < len(combinedHex); i += 160 {
		sb.WriteString(fmt.Sprintf("b.hexBytes(\"%s\");\n", combinedHex[i:i+160]))
	}

	return sb.String(), nil
}

func PrintArkHex2Proof(proof *serialize.ArkHex2Proof) (string, error) {
	/*
		arkProof, err := proof.ToArk()
		if err != nil {
			return "", err
		}
		bProof, witness, err := serialize.FromJsonArkProof(arkProof)
		if err != nil {
			return "", err
		}*/
	piASerialized, err := serializeG1(&proof.Ar)
	if err != nil {
		return "", err
	}
	piCSerialized, err := serializeG1(&proof.Krs)
	if err != nil {
		return "", err
	}

	piBSerialized, err := serializeG2(&proof.Bs)

	if err != nil {
		return "", err
	}
	final := fmt.Sprintf(`b.hexBytes("%s").tag("π_A");
b.hexBytes("%s").tag("π_B_A0");
b.hexBytes("%s").tag("π_B_A1");
b.hexBytes("%s").tag("π_C");
b.hexBytes("%s").tag("public_input_0");
b.hexBytes("%s").tag("public_input_1");`, piASerialized, piBSerialized[:96], piBSerialized[96:], piCSerialized, reverseHexString(proof.Witness[0]), reverseHexString(proof.Witness[1]))
	return final, nil

}
