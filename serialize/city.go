package serialize

import (
	fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
)

type CityGroth16ProofData struct {
	PiA   string `json:"pi_a"`
	PiBA0 string `json:"pi_b_a0"`
	PiBA1 string `json:"pi_b_a1"`
	PiC   string `json:"pi_c"`
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
	}, nil
}
