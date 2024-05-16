package serialize

import (
	"fmt"
	"math/big"
)

type ArkHexVK struct {
	AlphaG1 string `json:"alpha_g1"`
	BetaG2  string `json:"beta_g2"`
	GammaG2 string `json:"gamma_g2"`
	DeltaG2 string `json:"delta_g2"`
	// length dependent on circuit public inputs
	G1K []string `json:"k"`
}
type ArkHexProof struct {
	Ar      string   `json:"pi_a"`
	Bs      string   `json:"pi_b"`
	Krs     string   `json:"pi_c"`
	Witness []string `json:"public_inputs"`
}

func hexToBigInt(hex string) (*big.Int, error) {
	n, success := big.NewInt(0).SetString(hex, 16)
	if success {
		return n, nil
	} else {
		return nil, fmt.Errorf("invalid hex string: %s", hex)
	}
}

/*
func deserializeArkHexG1(g string) (*bls12381.G1Affine, error) {
	if len(g) != 192 {
		return nil, fmt.Errorf("invalid G1 point length %d", len(g))
	}
	xBytes, err := hex.DecodeString(g[:96])
	if err != nil {
		return nil, err
	}
	x, err := fp.BigEndian.Element((*[48]byte)(xBytes))
	if err != nil {
		return nil, err
	}
	yBytes, err := hex.DecodeString(g[96:])
	if err != nil {
		return nil, err
	}
	y, err := fp.BigEndian.Element((*[48]byte)(yBytes))
	if err != nil {
		return nil, err
	}
	return &bls12381.G1Affine{X: x, Y: y}, nil
}

func deserializeArkHexG2(g string) (*bls12381.G2Affine, error) {
	if len(g) != 384 {
		return nil, fmt.Errorf("invalid G1 point length %d", len(g))
	}
	a0Bytes, err := hex.DecodeString(g[:96])
	if err != nil {
		return nil, err
	}
	xA0, err := fp.BigEndian.Element((*[48]byte)(a0Bytes))
	if err != nil {
		return nil, err
	}
	a1Bytes, err := hex.DecodeString(g[96:192])
	if err != nil {
		return nil, err
	}
	xA1, err := fp.BigEndian.Element((*[48]byte)(a1Bytes))
	if err != nil {
		return nil, err
	}
	a0Bytes, err = hex.DecodeString(g[192:288])
	if err != nil {
		return nil, err
	}
	yA0, err := fp.BigEndian.Element((*[48]byte)(a0Bytes))
	if err != nil {
		return nil, err
	}
	a1Bytes, err = hex.DecodeString(g[288:384])
	if err != nil {
		return nil, err
	}
	yA1, err := fp.BigEndian.Element((*[48]byte)(a1Bytes))
	if err != nil {
		return nil, err
	}
	g2 := &bls12381.G2Affine{}
	g2.X.A0 = xA0
	g2.X.A1 = xA1
	g2.Y.A0 = yA0
	g2.Y.A1 = yA1
	return g2, nil
}*/

func deserializeArkHexG1(g string) (*ArkProofG1, error) {
	if len(g) != 192 {
		return nil, fmt.Errorf("invalid G1 point length %d", len(g))
	}
	x, err := hexToBigInt(g[:96])
	if err != nil {
		return nil, err
	}
	y, err := hexToBigInt(g[96:])
	if err != nil {
		return nil, err
	}
	return &ArkProofG1{X: x.String(), Y: y.String()}, nil
}

func deserializeArkHexG2(g string) (*ArkProofG2, error) {
	if len(g) != 384 {
		return nil, fmt.Errorf("invalid G1 point length %d", len(g))
	}
	xA0, err := hexToBigInt(g[:96])
	if err != nil {
		return nil, err
	}
	xA1, err := hexToBigInt(g[96:192])
	if err != nil {
		return nil, err
	}
	yA0, err := hexToBigInt(g[192:288])
	if err != nil {
		return nil, err
	}
	yA1, err := hexToBigInt(g[288:384])
	if err != nil {
		return nil, err
	}
	g2 := &ArkProofG2{}
	/*
		g2.X.A0 = xA0.String()
		g2.X.A1 = xA1.String()
		g2.Y.A0 = yA0.String()
		g2.Y.A1 = yA1.String()
	*/
	g2.X.A0 = xA1.String()
	g2.X.A1 = xA0.String()
	g2.Y.A0 = yA1.String()
	g2.Y.A1 = yA0.String()
	return g2, nil
}
func (p *ArkHexProof) ArkHexProofToArk() (*ArkProof, error) {
	proof := new(ArkProof)
	proof.Witness = make([]string, len(p.Witness))
	for i, w := range p.Witness {
		if len(w) != 64 {
			return nil, fmt.Errorf("invalid witness length %d", len(w))
		}

		frv, err := hexToBigInt(w)
		if err != nil {
			return nil, err
		}
		proof.Witness[i] = frv.String()
	}
	ar, err := deserializeArkHexG1(p.Ar)
	if err != nil {
		return nil, err
	}
	bs, err := deserializeArkHexG2(p.Bs)
	if err != nil {
		return nil, err
	}
	kr, err := deserializeArkHexG1(p.Krs)
	if err != nil {
		return nil, err
	}
	proof.Ar = *ar
	proof.Bs = *bs
	proof.Krs = *kr
	return proof, nil
}

func (v *ArkHexVK) ArkHexVKToArk() (*ArkVK, error) {
	ark := new(ArkVK)
	alphaG1, err := deserializeArkHexG1(v.AlphaG1)
	if err != nil {
		return nil, err
	}
	betaG2, err := deserializeArkHexG2(v.BetaG2)
	if err != nil {
		return nil, err
	}
	gammaG2, err := deserializeArkHexG2(v.GammaG2)
	if err != nil {
		return nil, err
	}
	deltaG2, err := deserializeArkHexG2(v.DeltaG2)
	if err != nil {
		return nil, err
	}
	ark.AlphaG1 = *alphaG1
	ark.BetaG2 = *betaG2
	ark.GammaG2 = *gammaG2
	ark.DeltaG2 = *deltaG2
	ark.G1K = make([]ArkProofG1, len(v.G1K))
	for i, g := range v.G1K {
		g1, err := deserializeArkHexG1(g)
		if err != nil {
			return nil, err
		}
		ark.G1K[i] = *g1
	}
	return ark, nil
}
