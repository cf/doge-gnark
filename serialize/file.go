package serialize

import (
	"encoding/json"
	"fmt"
	"os"

	fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	groth16_bls12381 "github.com/zilong-dai/gnark/backend/groth16/bls12-381"
)

// START: ARK Base Format
func SaveArkProof(proof *groth16_bls12381.Proof, witness []fr.Element, path string) error {
	arkProof := ToJsonArkProof(proof, witness)
	data, err := json.MarshalIndent(arkProof, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func LoadArkProof(path string) (*groth16_bls12381.Proof, []fr.Element, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	arkProof := new(ArkProof)
	err = json.Unmarshal(data, arkProof)
	if err != nil {
		return nil, nil, err
	}
	return FromJsonArkProof(arkProof)
}

func SaveArkVK(vk *groth16_bls12381.VerifyingKey, path string) error {
	arkVK := ToJsonArkVK(vk)
	data, err := json.MarshalIndent(arkVK, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func LoadArkVK(path string) (*groth16_bls12381.VerifyingKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	arkVK := new(ArkVK)
	err = json.Unmarshal(data, arkVK)
	if err != nil {
		return nil, err
	}
	return FromJsonArkVK(arkVK)
}

// END: ARK Base Format

// START: ARK Hex Format
func SaveArkHexProof(proof *groth16_bls12381.Proof, witness []fr.Element, path string) error {
	arkProof := ToJsonArkProof(proof, witness)
	data, err := json.MarshalIndent(arkProof, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func LoadArkHexProof(path string) (*groth16_bls12381.Proof, []fr.Element, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	arkProof := new(ArkHexProof)
	err = json.Unmarshal(data, arkProof)
	if err != nil {
		return nil, nil, err
	}
	aProof, err := arkProof.ArkHexProofToArk()
	if err != nil {
		return nil, nil, err
	}

	return FromJsonArkProof(aProof)
}

func SaveArkHexVK(vk *groth16_bls12381.VerifyingKey, path string) error {
	arkVK := ToJsonArkVK(vk)
	data, err := json.MarshalIndent(arkVK, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func LoadArkHexVK(path string) (*groth16_bls12381.VerifyingKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	arkVK := new(ArkHexVK)
	err = json.Unmarshal(data, arkVK)
	if err != nil {
		return nil, err
	}
	aVK, err := arkVK.ArkHexVKToArk()
	if err != nil {
		return nil, err
	}
	return FromJsonArkVK(aVK)
}

// END: ARK Hex Format

// START: ARK Hex2 Format
func SaveArkHex2Proof(proof *groth16_bls12381.Proof, witness []fr.Element, path string) error {
	arkProof := ToJsonArkProof(proof, witness)
	arkHex2Proof := arkProof.ToArkHex2Proof()
	data, err := json.MarshalIndent(arkHex2Proof, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func LoadArkHex2Proof(path string) (*groth16_bls12381.Proof, []fr.Element, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	arkProof := new(ArkHex2Proof)
	err = json.Unmarshal(data, arkProof)
	if err != nil {
		return nil, nil, err
	}
	aProof, err := arkProof.ToArk()
	if err != nil {
		return nil, nil, err
	}

	return FromJsonArkProof(aProof)
}

func SaveArkHex2VK(vk *groth16_bls12381.VerifyingKey, path string) error {
	arkVK := ToJsonArkVK(vk)
	arkHex2VK := arkVK.ToArkHex2VK()
	data, err := json.MarshalIndent(arkHex2VK, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func LoadArkHex2VK(path string) (*groth16_bls12381.VerifyingKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	arkVK := new(ArkHex2VK)
	err = json.Unmarshal(data, arkVK)
	if err != nil {
		return nil, err
	}
	aVK, err := arkVK.ToArk()
	if err != nil {
		return nil, err
	}
	return FromJsonArkVK(aVK)
}

// END: ARK Hex2 Format

// START: Circom Format
func SaveCircomProof(proof *groth16_bls12381.Proof, witness []fr.Element, path string) error {
	arkProof := ToJsonArkProof(proof, witness)
	circomProof := arkProof.ArkProofToCircom()
	data, err := json.MarshalIndent(circomProof, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
func LoadCircomProof(path string) (*groth16_bls12381.Proof, []fr.Element, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	arkProof := new(CircomProof)
	err = json.Unmarshal(data, arkProof)
	if err != nil {
		return nil, nil, err
	}
	return FromJsonArkProof(arkProof.CircomProofToArk())
}
func SaveCircomVK(vk *groth16_bls12381.VerifyingKey, path string) error {
	arkVK := ToJsonArkVK(vk)
	circomVK := arkVK.ArkVKToCircom()
	data, err := json.MarshalIndent(circomVK, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
func LoadCircomVK(path string) (*groth16_bls12381.VerifyingKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	circomVK := new(CircomVK)
	err = json.Unmarshal(data, circomVK)
	if err != nil {
		return nil, err
	}
	return FromJsonArkVK(circomVK.CircomVKToArk())
}

// END: Circom Format

// START: Generic Proof Loading and Saving
func SaveProof(proof *groth16_bls12381.Proof, witness []fr.Element, format ProofSerializationFormat, path string) error {
	switch format {
	case Ark:
		return SaveArkProof(proof, witness, path)
	case Circom:
		return SaveCircomProof(proof, witness, path)
	case ArkHex:
		return SaveArkProof(proof, witness, path)
	case ArkHex2:
		return SaveArkHex2Proof(proof, witness, path)
	}
	return fmt.Errorf("unsupported proof serialization format: %s", format.String())
}

func LoadProof(path string, format ProofSerializationFormat) (*groth16_bls12381.Proof, []fr.Element, error) {
	switch format {
	case Ark:
		return LoadArkProof(path)
	case Circom:
		return LoadCircomProof(path)
	case ArkHex:
		return LoadArkHexProof(path)
	case ArkHex2:
		return LoadArkHex2Proof(path)
	}
	return nil, nil, fmt.Errorf("unsupported proof serialization format: %s", format.String())
}

func SaveVK(vk *groth16_bls12381.VerifyingKey, format ProofSerializationFormat, path string) error {
	switch format {
	case Ark:
		return SaveArkVK(vk, path)
	case Circom:
		return SaveCircomVK(vk, path)
	case ArkHex:
		return SaveArkHexVK(vk, path)
	case ArkHex2:
		return SaveArkHex2VK(vk, path)
	}
	return fmt.Errorf("unsupported proof serialization format: %s", format.String())
}

func LoadVK(path string, format ProofSerializationFormat) (*groth16_bls12381.VerifyingKey, error) {
	switch format {
	case Ark:
		return LoadArkVK(path)
	case Circom:
		return LoadCircomVK(path)
	case ArkHex:
		return LoadArkHexVK(path)
	case ArkHex2:
		return LoadArkHex2VK(path)
	}
	return nil, fmt.Errorf("unsupported proof serialization format: %s", format.String())
}

// END: Generic Proof Loading and Saving
