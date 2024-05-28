package serialize

import (
	"fmt"
	fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	groth16_bls12381 "github.com/zilong-dai/gnark/backend/groth16/bls12-381"
)

type CityGroth16ProofData struct {
	PiA          string `json:"pi_a"`
	PiBA0        string `json:"pi_b_a0"`
	PiBA1        string `json:"pi_b_a1"`
	PiC          string `json:"pi_c"`
	PublicInput0 string `json:"public_input_0"`
	PublicInput1 string `json:"public_input_1"`
}

type CityGroth16VerifierData struct {
	AlphaG1 string `json:"alpha_g1"`
	BetaG2  string `json:"beta_g2"`
	GammaG2 string `json:"gamma_g2"`
	DeltaG2 string `json:"delta_g2"`
	G1K0    string `json:"k0"`
	G1K1    string `json:"k1"`
}

func ToJsonCityProof(p *groth16_bls12381.Proof, witness []fr.Element) (*CityGroth16ProofData, error) {
	arkProof := ToJsonArkProof(p, witness)

	arkHex2Proof := arkProof.ToArkHex2Proof()

	piASerialized, err := SerializeG1(&arkHex2Proof.Ar)
	if err != nil {
		return nil, err
	}

	piBSerialized, err := SerializeG2(&arkHex2Proof.Bs)
	if err != nil {
		return nil, err
	}

	piCSerialized, err := SerializeG1(&arkHex2Proof.Krs)
	if err != nil {
		return nil, err
	}

	return &CityGroth16ProofData{
		piASerialized,
		piBSerialized[:96],
		piBSerialized[96:],
		piCSerialized,
		ReverseHexString(arkHex2Proof.Witness[0]),
		ReverseHexString(arkHex2Proof.Witness[1]),
	}, nil
}

func ToJsonCityVK(vk *groth16_bls12381.VerifyingKey) (*CityGroth16VerifierData, error) {
	arkVk := ToJsonArkVK(vk)

	arkHex2VK := arkVk.ToArkHex2VK()

	AlphaG1, err := SerializeG1(&arkHex2VK.AlphaG1)
	if err != nil {
		return nil, err
	}

	if len(arkHex2VK.G1K) != 2 {
		return nil, fmt.Errorf("invalid G1K length %d, expected 2", len(arkHex2VK.G1K))
	}

	G1K0, err := SerializeG1(&arkHex2VK.G1K[0])
	if err != nil {
		return nil, err
	}
	G1K1, err := SerializeG1(&arkHex2VK.G1K[1])
	if err != nil {
		return nil, err
	}

	BetaG2, err := SerializeG2(&arkHex2VK.BetaG2)
	if err != nil {
		return nil, err
	}
	GammaG2, err := SerializeG2(&arkHex2VK.GammaG2)
	if err != nil {
		return nil, err
	}
	DeltaG2, err := SerializeG2(&arkHex2VK.DeltaG2)
	if err != nil {
		return nil, err
	}

	return &CityGroth16VerifierData{
		AlphaG1,
		BetaG2,
		GammaG2,
		DeltaG2,
		G1K0,
		G1K1,
	}, nil
}
