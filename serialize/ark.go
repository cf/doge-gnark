package serialize

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
)

type ArkProofE2 struct {
	A0 string `json:"a0"`
	A1 string `json:"a1"`
}
type ArkProofG1 struct {
	X string `json:"x"`
	Y string `json:"y"`
}
type ArkProofG2 struct {
	X ArkProofE2 `json:"x"`
	Y ArkProofE2 `json:"y"`
}
type ArkVK struct {
	AlphaG1 ArkProofG1 `json:"alpha_g1"`
	BetaG2  ArkProofG2 `json:"beta_g2"`
	GammaG2 ArkProofG2 `json:"gamma_g2"`
	DeltaG2 ArkProofG2 `json:"delta_g2"`
	// length dependent on circuit public inputs
	G1K []ArkProofG1 `json:"k"`
}
type ArkProof struct {
	Ar      ArkProofG1 `json:"pi_a"`
	Bs      ArkProofG2 `json:"pi_b"`
	Krs     ArkProofG1 `json:"pi_c"`
	Witness []string   `json:"public_inputs"`
}

func toJsonArkG1(g *bls12381.G1Affine) *ArkProofG1 {
	g1 := new(ArkProofG1)
	g1.X = g.X.String()
	g1.Y = g.Y.String()
	return g1
}

func toJsonArkE2(g *bls12381.E2) *ArkProofE2 {
	g1 := new(ArkProofE2)
	g1.A0 = g.A0.String()
	g1.A1 = g.A1.String()
	return g1
}
func toJsonArkFr(x *fr.Element) string {
	a := x.String()
	return a
}
func toJsonArkG2(j bls12381.G2Affine) *ArkProofG2 {
	g := new(ArkProofG2)
	g.X = *toJsonArkE2(&j.X)
	g.Y = *toJsonArkE2(&j.Y)
	return g
}
func ToJsonArkProof(p *groth16_bls12381.Proof, witness []fr.Element) *ArkProof {
	proof := new(ArkProof)
	proof.Ar = *toJsonArkG1(&p.Ar)
	proof.Bs = *toJsonArkG2(p.Bs)
	proof.Krs = *toJsonArkG1(&p.Krs)
	proof.Witness = make([]string, len(witness))
	for i, w := range witness {
		proof.Witness[i] = toJsonArkFr(&w)
	}
	return proof
}
func ToJsonArkVK(vk *groth16_bls12381.VerifyingKey) *ArkVK {
	v := new(ArkVK)
	v.AlphaG1 = *toJsonArkG1(&vk.G1.Alpha)
	v.BetaG2 = *toJsonArkG2(vk.G2.Beta)
	v.GammaG2 = *toJsonArkG2(vk.G2.Gamma)
	v.DeltaG2 = *toJsonArkG2(vk.G2.Delta)
	v.G1K = make([]ArkProofG1, len(vk.G1.K))
	for i, g := range vk.G1.K {
		v.G1K[i] = *toJsonArkG1(&g)
	}
	return v
}
func FromJsonArkFr(j string) (*fr.Element, error) {
	x := new(fr.Element)
	x.SetString(j)
	return x, nil
}
func fromJsonArkG1(j *ArkProofG1) (*bls12381.G1Affine, error) {
	x := new(bls12381.G1Affine)
	x.X.SetString(j.X)
	x.Y.SetString(j.Y)
	return x, nil
}
func FromJsonArkE2(j *ArkProofE2) (*bls12381.E2, error) {
	x := new(bls12381.E2)
	x.A0.SetString(j.A0)
	x.A1.SetString(j.A1)
	return x, nil
}

func fromJsonArkG2(j *ArkProofG2) (*bls12381.G2Affine, error) {
	x := new(bls12381.G2Affine)
	y, err := FromJsonArkE2(&j.X)
	if err != nil {
		return nil, err
	}
	x.X = *y
	y, err = FromJsonArkE2(&j.Y)
	if err != nil {
		return nil, err
	}
	x.Y = *y
	return x, nil
}
func FromJsonArkProof(j *ArkProof) (*groth16_bls12381.Proof, []fr.Element, error) {
	proof := &groth16_bls12381.Proof{}
	witness := make([]fr.Element, len(j.Witness))
	proof.Commitments = make([]bls12381.G1Affine, 0)

	for i, w := range j.Witness {
		x, err := FromJsonArkFr(w)
		if err != nil {
			return nil, nil, err
		}
		witness[i] = *x
	}
	ar, err := fromJsonArkG1(&j.Ar)
	if err != nil {
		return nil, nil, err
	}
	proof.Ar = *ar
	bs, err := fromJsonArkG2(&j.Bs)
	if err != nil {
		return nil, nil, err
	}
	proof.Bs = *bs
	krs, err := fromJsonArkG1(&j.Krs)
	if err != nil {
		return nil, nil, err
	}
	proof.Krs = *krs
	return proof, witness, nil
}
func FromJsonArkVK(j *ArkVK) (*groth16_bls12381.VerifyingKey, error) {
	vk := &groth16_bls12381.VerifyingKey{}
	alpha, err := fromJsonArkG1(&j.AlphaG1)
	if err != nil {
		return nil, err
	}
	vk.G1.Alpha = *alpha
	beta, err := fromJsonArkG2(&j.BetaG2)
	if err != nil {
		return nil, err
	}
	vk.G2.Beta = *beta
	gamma, err := fromJsonArkG2(&j.GammaG2)
	if err != nil {
		return nil, err
	}
	vk.G2.Gamma = *gamma
	delta, err := fromJsonArkG2(&j.DeltaG2)
	if err != nil {
		return nil, err
	}
	vk.G2.Delta = *delta
	vk.G1.K = make([]bls12381.G1Affine, len(j.G1K))
	for i, g := range j.G1K {
		x, err := fromJsonArkG1(&g)
		if err != nil {
			return nil, err
		}
		vk.G1.K[i] = *x
	}
	vk.Precompute()

	return vk, nil
}
