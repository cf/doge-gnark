package btcprint

import (
	"doge-covenant/serialize"
	"fmt"
	"strings"
)


func PrintArkHex2VK(vk *serialize.ArkHex2VK) (string, error) {
	var sb strings.Builder
	piAlphaG1, err := serialize.SerializeG1(&vk.AlphaG1)
	if err != nil {
		return "", err
	}
	sb.WriteString(piAlphaG1)

	for _, g1 := range vk.G1K {
		piG1, err := serialize.SerializeG1(&g1)
		if err != nil {
			return "", err
		}

		sb.WriteString(piG1)
	}
	bg2, err := serialize.SerializeG2(&vk.BetaG2)
	if err != nil {
		return "", err
	}
	dg2, err := serialize.SerializeG2(&vk.DeltaG2)
	if err != nil {
		return "", err
	}
	gg2, err := serialize.SerializeG2(&vk.GammaG2)
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
	piASerialized, err := serialize.SerializeG1(&proof.Ar)
	if err != nil {
		return "", err
	}
	piCSerialized, err := serialize.SerializeG1(&proof.Krs)
	if err != nil {
		return "", err
	}

	piBSerialized, err := serialize.SerializeG2(&proof.Bs)

	if err != nil {
		return "", err
	}
	final := fmt.Sprintf(`b.hexBytes("%s").tag("π_A");
b.hexBytes("%s").tag("π_B_A0");
b.hexBytes("%s").tag("π_B_A1");
b.hexBytes("%s").tag("π_C");
b.hexBytes("%s").tag("public_input_0");
b.hexBytes("%s").tag("public_input_1");`, piASerialized, piBSerialized[:96], piBSerialized[96:], piCSerialized, serialize.ReverseHexString(proof.Witness[0]), serialize.ReverseHexString(proof.Witness[1]))
	return final, nil

}
