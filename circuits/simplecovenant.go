package circuits

import (
	"bytes"
	"crypto/sha256"
	sha256gadget "github.com/GopherJ/doge-covenant/sha256"
	"encoding/hex"
	"log"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/zilong-dai/gnark/backend/groth16"
	groth16_bls12381 "github.com/zilong-dai/gnark/backend/groth16/bls12-381"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"

	"github.com/zilong-dai/gnark/std/math/uints"
)

type simpleCovenantCircuit struct {
	//txid
	Pub0 frontend.Variable `gnark:",public"`
	Pub1 frontend.Variable `gnark:",public"`

	PreImage         []uints.U8 `gnark:",secret"`
	ConstrainTxBytes []byte
	ConstrainIndex   int
}

func (circuit *simpleCovenantCircuit) Define(api frontend.API) error {
	hasher := sha256gadget.New(api)
	feVars := make([]frontend.Variable, len(circuit.PreImage))
	for i := 0; i < len(circuit.PreImage); i++ {
		feVars[i] = circuit.PreImage[i].Val
	}
	hasher.Write(feVars[:])
	hash := hasher.Sum()
	hasher = sha256gadget.New(api)
	hasher.Write(hash)
	hash = hasher.Sum()

	acc := api.Add(big.NewInt(0), big.NewInt(0))

	nbBytes := 31
	for i := 0; i < nbBytes; i++ {
		power := new(big.Int).Lsh(big.NewInt(1), uint(i*8)).String()
		acc = api.Add(acc, api.Mul(power, hash[i]))
	}

	api.AssertIsEqual(circuit.Pub1, acc)
	api.AssertIsEqual(circuit.Pub0, circuit.Pub1)

	return nil
}

/*
func (circuit *simpleSha256Circuit) Define(api frontend.API) error {
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}
	hasher.Write(circuit.PreImage[:])
	hash := hasher.Sum()
	// number of bits of exponent

	acc := api.Add(big.NewInt(0), big.NewInt(0))

	nbBytes := 31
	for i := 0; i < nbBytes; i++ {
		power := new(big.Int).Lsh(big.NewInt(1), uint(i*8)).String()
		acc = api.Add(acc, api.Mul(power, hash[i].Val))
	}

	api.AssertIsEqual(circuit.Pub1, acc)
	api.AssertIsEqual(circuit.Pub0, circuit.Pub1)

	return nil
}*/

func calcResultSimpleCovenant(preImage []byte) *big.Int {
	hasher := sha256.New()
	hasher.Write(preImage)
	result := hasher.Sum([]byte{})
	resultB := sha256.Sum256(result)
	resultTruncated := resultB[:31]
	log.Printf("hex result: %s", hex.EncodeToString(resultTruncated))
	acc := big.NewInt(0)
	for i := 0; i < 31; i++ {
		power := new(big.Int).Lsh(big.NewInt(1), uint(i*8))
		acc = acc.Add(acc, new(big.Int).Mul(power, big.NewInt(int64(resultTruncated[i]))))
	}
	log.Printf("result: %s", acc.String())
	return acc
}
func ProveSimpleCovenantircuit(preImage []byte, mode int, provingKeyPath string, verifierKeyPath string, constrainIndex int, constrainTxBytes []byte) (*groth16_bls12381.Proof, *groth16_bls12381.VerifyingKey, []fr.Element, error) {

	var circuit simpleCovenantCircuit
	circuit.ConstrainIndex = constrainIndex
	circuit.ConstrainTxBytes = constrainTxBytes
	circuit.PreImage = uints.NewU8Array(preImage)

	// // building the circuit...
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, err
	}
	{
		var w simpleCovenantCircuit
		hashResult := calcResultSimpleCovenant(preImage)
		w.Pub0 = hashResult
		w.Pub1 = hashResult
		w.ConstrainIndex = constrainIndex
		w.ConstrainTxBytes = constrainTxBytes
		w.PreImage = uints.NewU8Array(preImage)
		witnessFull, err := frontend.NewWitness(&w, ecc.BLS12_381.ScalarField())
		if err != nil {
			return nil, nil, nil, err
		}

		witnessPublic, err := frontend.NewWitness(&w, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
		if err != nil {
			return nil, nil, nil, err
		}

		var pk groth16.ProvingKey
		var vk groth16.VerifyingKey
		if mode != 2 {
			pk, vk, err = groth16.Setup(ccs)
			if err != nil {
				return nil, nil, nil, err
			}

			if mode == 1 {
				var bufPk bytes.Buffer
				pk.WriteTo(&bufPk)
				err = os.WriteFile(provingKeyPath, bufPk.Bytes(), 0644)
				if err != nil {
					return nil, nil, nil, err
				}
				var bufVk bytes.Buffer
				vk.WriteTo(&bufVk)
				err = os.WriteFile(verifierKeyPath, bufVk.Bytes(), 0644)
				if err != nil {
					return nil, nil, nil, err
				}
			}
		} else {
			pk = groth16.NewProvingKey(ecc.BLS12_381)
			provingKeyFile, err := os.OpenFile(provingKeyPath, os.O_RDONLY, 0644)
			if err != nil {
				return nil, nil, nil, err
			}
			_, err = pk.ReadFrom(provingKeyFile)
			defer provingKeyFile.Close()
			if err != nil {
				return nil, nil, nil, err
			}

			verifierKeyFile, err := os.OpenFile(verifierKeyPath, os.O_RDONLY, 0644)
			if err != nil {
				return nil, nil, nil, err
			}
			vk = groth16.NewVerifyingKey(ecc.BLS12_381)

			_, err = vk.ReadFrom(verifierKeyFile)
			defer verifierKeyFile.Close()
			if err != nil {
				return nil, nil, nil, err
			}
		}
		proof, err := groth16.Prove(ccs, pk, witnessFull)
		if err != nil {
			return nil, nil, nil, err
		}

		err = groth16.Verify(proof, vk, witnessPublic)
		if err != nil {
			return nil, nil, nil, err
		}

		blsProof := proof.(*groth16_bls12381.Proof)
		blsVk := vk.(*groth16_bls12381.VerifyingKey)
		blsWitness := witnessPublic.Vector().(fr.Vector)
		return blsProof, blsVk, blsWitness, nil
	}
}
