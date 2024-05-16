package serialize

type circomG1 = []string
type circomG2 = [][]string
type CircomVK struct {
	AlphaG1 circomG1 `json:"vk_alpha_1"`
	BetaG2  circomG2 `json:"vk_beta_2"`
	GammaG2 circomG2 `json:"vk_gamma_2"`
	DeltaG2 circomG2 `json:"vk_delta_2"`
	// length dependent on circuit public inputs
	G1K []circomG1 `json:"IC"`
}
type CircomProof struct {
	Ar      circomG1 `json:"pi_a"`
	Bs      circomG2 `json:"pi_b"`
	Krs     circomG1 `json:"pi_c"`
	Witness []string `json:"public_inputs"`
}

func (p *CircomProof) CircomProofToArk() *ArkProof {
	proof := new(ArkProof)
	proof.Ar.X = p.Ar[0]
	proof.Ar.Y = p.Ar[1]
	proof.Bs.X.A0 = p.Bs[0][0]
	proof.Bs.X.A1 = p.Bs[0][1]
	proof.Bs.Y.A0 = p.Bs[1][0]
	proof.Bs.Y.A1 = p.Bs[1][1]
	proof.Krs.X = p.Krs[0]
	proof.Krs.Y = p.Krs[1]
	proof.Witness = p.Witness
	return proof
}

func (p *ArkProof) ArkProofToCircom() *CircomProof {
	proof := new(CircomProof)
	proof.Ar = []string{p.Ar.X, p.Ar.Y, "1"}
	proof.Bs = [][]string{{p.Bs.X.A0, p.Bs.X.A1}, {p.Bs.Y.A0, p.Bs.Y.A1}, {"1", "0"}}
	proof.Krs = []string{p.Krs.X, p.Krs.Y, "1"}
	proof.Witness = p.Witness
	return proof
}
func (vk *CircomVK) CircomVKToArk() *ArkVK {
	ark := new(ArkVK)
	ark.AlphaG1.X = vk.AlphaG1[0]
	ark.AlphaG1.Y = vk.AlphaG1[1]
	ark.BetaG2.X.A0 = vk.BetaG2[0][0]
	ark.BetaG2.X.A1 = vk.BetaG2[0][1]
	ark.BetaG2.Y.A0 = vk.BetaG2[1][0]
	ark.BetaG2.Y.A1 = vk.BetaG2[1][1]
	ark.GammaG2.X.A0 = vk.GammaG2[0][0]
	ark.GammaG2.X.A1 = vk.GammaG2[0][1]
	ark.GammaG2.Y.A0 = vk.GammaG2[1][0]
	ark.GammaG2.Y.A1 = vk.GammaG2[1][1]
	ark.DeltaG2.X.A0 = vk.DeltaG2[0][0]
	ark.DeltaG2.X.A1 = vk.DeltaG2[0][1]
	ark.DeltaG2.Y.A0 = vk.DeltaG2[1][0]
	ark.DeltaG2.Y.A1 = vk.DeltaG2[1][1]
	ark.G1K = make([]ArkProofG1, len(vk.G1K))
	for i, g1 := range vk.G1K {
		ark.G1K[i].X = g1[0]
		ark.G1K[i].Y = g1[1]
	}
	return ark
}
func (vk *ArkVK) ArkVKToCircom() *CircomVK {
	circom := new(CircomVK)
	circom.AlphaG1 = []string{vk.AlphaG1.X, vk.AlphaG1.Y, "1"}
	circom.BetaG2 = [][]string{{vk.BetaG2.X.A0, vk.BetaG2.X.A1}, {vk.BetaG2.Y.A0, vk.BetaG2.Y.A1}, {"1", "0"}}
	circom.GammaG2 = [][]string{{vk.GammaG2.X.A0, vk.GammaG2.X.A1}, {vk.GammaG2.Y.A0, vk.GammaG2.Y.A1}, {"1", "0"}}
	circom.DeltaG2 = [][]string{{vk.DeltaG2.X.A0, vk.DeltaG2.X.A1}, {vk.DeltaG2.Y.A0, vk.DeltaG2.Y.A1}, {"1", "0"}}
	circom.G1K = make([]circomG1, len(vk.G1K))
	for i, g1 := range vk.G1K {
		circom.G1K[i] = []string{g1.X, g1.Y, "1"}
	}
	return circom
}
