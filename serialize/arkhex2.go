package serialize

import (
	"fmt"
	"math/big"
)

type ArkHex2ProofE2 struct {
	A0 string `json:"a0"`
	A1 string `json:"a1"`
}
type ArkHex2ProofG1 struct {
	X string `json:"x"`
	Y string `json:"y"`
}
type ArkHex2ProofG2 struct {
	X ArkHex2ProofE2 `json:"x"`
	Y ArkHex2ProofE2 `json:"y"`
}
type ArkHex2VK struct {
	AlphaG1 ArkHex2ProofG1 `json:"alpha_g1"`
	BetaG2  ArkHex2ProofG2 `json:"beta_g2"`
	GammaG2 ArkHex2ProofG2 `json:"gamma_g2"`
	DeltaG2 ArkHex2ProofG2 `json:"delta_g2"`
	// length dependent on circuit public inputs
	G1K []ArkHex2ProofG1 `json:"k"`
}
type ArkHex2Proof struct {
	Ar      ArkHex2ProofG1 `json:"pi_a"`
	Bs      ArkHex2ProofG2 `json:"pi_b"`
	Krs     ArkHex2ProofG1 `json:"pi_c"`
	Witness []string       `json:"public_inputs"`
}

func Base10ToHex(base10 string, padLength int) string {
	n := new(big.Int)
	n.SetString(base10, 10)
	return fmt.Sprintf("%0"+fmt.Sprintf("%d", padLength)+"x", n)

}
func deserializeArkHex2G1(g *ArkHex2ProofG1) (*ArkProofG1, error) {
	if len(g.X) != 96 || len(g.Y) != 96 {
		return nil, fmt.Errorf("invalid G1 point length %d,%d", len(g.X), len(g.Y))
	}
	x, err := hexToBigInt(g.X)
	if err != nil {
		return nil, err
	}
	y, err := hexToBigInt(g.Y)
	if err != nil {
		return nil, err
	}
	return &ArkProofG1{X: x.String(), Y: y.String()}, nil
}

func deserializeArkHex2G2(g *ArkHex2ProofG2) (*ArkProofG2, error) {
	if len(g.X.A0) != 96 {
		return nil, fmt.Errorf("invalid G1 point X.AO length %d", len(g.X.A0))
	}
	if len(g.X.A1) != 96 {
		return nil, fmt.Errorf("invalid G1 point X.A1 length %d", len(g.X.A1))
	}
	if len(g.Y.A0) != 96 {
		return nil, fmt.Errorf("invalid G1 point Y.AO length %d", len(g.Y.A0))
	}
	if len(g.Y.A1) != 96 {
		return nil, fmt.Errorf("invalid G1 point Y.A1 length %d", len(g.Y.A1))
	}
	xA0, err := hexToBigInt(g.X.A0)
	if err != nil {
		return nil, err
	}
	xA1, err := hexToBigInt(g.X.A1)
	if err != nil {
		return nil, err
	}
	yA0, err := hexToBigInt(g.Y.A0)
	if err != nil {
		return nil, err
	}
	yA1, err := hexToBigInt(g.Y.A1)
	if err != nil {
		return nil, err
	}
	g2 := &ArkProofG2{}
	g2.X.A0 = xA0.String()
	g2.X.A1 = xA1.String()
	g2.Y.A0 = yA0.String()
	g2.Y.A1 = yA1.String()
	return g2, nil
}
func (p *ArkHex2Proof) ToArk() (*ArkProof, error) {
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
	ar, err := deserializeArkHex2G1(&p.Ar)
	if err != nil {
		return nil, err
	}
	bs, err := deserializeArkHex2G2(&p.Bs)
	if err != nil {
		return nil, err
	}
	kr, err := deserializeArkHex2G1(&p.Krs)
	if err != nil {
		return nil, err
	}
	proof.Ar = *ar
	proof.Bs = *bs
	proof.Krs = *kr
	return proof, nil
}

func (v *ArkHex2VK) ToArk() (*ArkVK, error) {
	ark := new(ArkVK)
	alphaG1, err := deserializeArkHex2G1(&v.AlphaG1)
	if err != nil {
		return nil, err
	}
	betaG2, err := deserializeArkHex2G2(&v.BetaG2)
	if err != nil {
		return nil, err
	}
	gammaG2, err := deserializeArkHex2G2(&v.GammaG2)
	if err != nil {
		return nil, err
	}
	deltaG2, err := deserializeArkHex2G2(&v.DeltaG2)
	if err != nil {
		return nil, err
	}
	ark.AlphaG1 = *alphaG1
	ark.BetaG2 = *betaG2
	ark.GammaG2 = *gammaG2
	ark.DeltaG2 = *deltaG2
	ark.G1K = make([]ArkProofG1, len(v.G1K))
	for i, g := range v.G1K {
		g1, err := deserializeArkHex2G1(&g)
		if err != nil {
			return nil, err
		}
		ark.G1K[i] = *g1
	}
	return ark, nil
}
func (ap *ArkProof) ToArkHex2Proof() *ArkHex2Proof {
	proof := new(ArkHex2Proof)
	proof.Ar.X = Base10ToHex(ap.Ar.X, 96)
	proof.Ar.Y = Base10ToHex(ap.Ar.Y, 96)
	proof.Bs.X.A0 = Base10ToHex(ap.Bs.X.A0, 96)
	proof.Bs.X.A1 = Base10ToHex(ap.Bs.X.A1, 96)
	proof.Bs.Y.A0 = Base10ToHex(ap.Bs.Y.A0, 96)
	proof.Bs.Y.A1 = Base10ToHex(ap.Bs.Y.A1, 96)
	proof.Krs.X = Base10ToHex(ap.Krs.X, 96)
	proof.Krs.Y = Base10ToHex(ap.Krs.Y, 96)
	proof.Witness = make([]string, len(ap.Witness))
	for i, w := range ap.Witness {
		proof.Witness[i] = Base10ToHex(w, 64)
	}
	return proof
}
func (vk *ArkVK) ToArkHex2VK() *ArkHex2VK {
	ark := new(ArkHex2VK)
	ark.AlphaG1.X = Base10ToHex(vk.AlphaG1.X, 96)
	ark.AlphaG1.Y = Base10ToHex(vk.AlphaG1.Y, 96)
	ark.BetaG2.X.A0 = Base10ToHex(vk.BetaG2.X.A0, 96)
	ark.BetaG2.X.A1 = Base10ToHex(vk.BetaG2.X.A1, 96)
	ark.BetaG2.Y.A0 = Base10ToHex(vk.BetaG2.Y.A0, 96)
	ark.BetaG2.Y.A1 = Base10ToHex(vk.BetaG2.Y.A1, 96)
	ark.GammaG2.X.A0 = Base10ToHex(vk.GammaG2.X.A0, 96)
	ark.GammaG2.X.A1 = Base10ToHex(vk.GammaG2.X.A1, 96)
	ark.GammaG2.Y.A0 = Base10ToHex(vk.GammaG2.Y.A0, 96)
	ark.GammaG2.Y.A1 = Base10ToHex(vk.GammaG2.Y.A1, 96)
	ark.DeltaG2.X.A0 = Base10ToHex(vk.DeltaG2.X.A0, 96)
	ark.DeltaG2.X.A1 = Base10ToHex(vk.DeltaG2.X.A1, 96)
	ark.DeltaG2.Y.A0 = Base10ToHex(vk.DeltaG2.Y.A0, 96)
	ark.DeltaG2.Y.A1 = Base10ToHex(vk.DeltaG2.Y.A1, 96)
	ark.G1K = make([]ArkHex2ProofG1, len(vk.G1K))
	for i, g1 := range vk.G1K {
		ark.G1K[i].X = Base10ToHex(g1.X, 96)
		ark.G1K[i].Y = Base10ToHex(g1.Y, 96)
	}
	return ark
}
