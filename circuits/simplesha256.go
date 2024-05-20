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
	"github.com/consensys/gnark/backend/groth16"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/consensys/gnark/std/math/uints"
)

type simpleSha256Circuit struct {
	PreImage []uints.U8        `gnark:",secret"`
	Pub0     frontend.Variable `gnark:",public"`
	Pub1     frontend.Variable `gnark:",public"`
}

func (circuit *simpleSha256Circuit) Define(api frontend.API) error {
	hasher := sha256gadget.New(api)
	feVars := make([]frontend.Variable, len(circuit.PreImage))
	for i := 0; i < len(circuit.PreImage); i++ {
		feVars[i] = circuit.PreImage[i].Val
	}
	hasher.Write(feVars[:])
	hash := hasher.Sum()

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

func calcResultSimpleSha256(preImage []byte) *big.Int {
	hasher := sha256.New()
	hasher.Write(preImage)
	result := hasher.Sum([]byte{})
	resultTruncated := result[:31]
	log.Printf("hex result: %s", hex.EncodeToString(resultTruncated))
	acc := big.NewInt(0)
	for i := 0; i < 31; i++ {
		power := new(big.Int).Lsh(big.NewInt(1), uint(i*8))
		acc = acc.Add(acc, new(big.Int).Mul(power, big.NewInt(int64(resultTruncated[i]))))
	}
	log.Printf("result: %s", acc.String())
	return acc
}
func ProveSimpleSha256Circuit(preImage []byte, mode int, provingKeyPath string, verifierKeyPath string) (*groth16_bls12381.Proof, *groth16_bls12381.VerifyingKey, []fr.Element, error) {

	var circuit simpleSha256Circuit
	circuit.PreImage = uints.NewU8Array(preImage)

	// // building the circuit...
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, err
	}
	{
		var w simpleSha256Circuit
		hashResult := calcResultSimpleSha256(preImage)
		w.Pub0 = hashResult
		w.Pub1 = hashResult
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

		/*
			vkjson, err := btcsnark.GetVerifyingKeyJsonBls(vk.(*groth16_bls12381.VerifyingKey))
			if err != nil {
				log.Fatal(err)
			}*/
		//fmt.Println("verifying key: ", string(vkjson[:]))
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
		/*
			err = groth16_bls12381.Verify(blsProof, blsVk, blsWitness)

			if err != nil {
				log.Fatal(err)
				return nil, nil, nil, err
			}
				arkProof := serialize.ToJsonArkProof(blsProof, blsWitness)
				arkVk := serialize.ToJsonArkVK(blsVk)
				reconArkProof, reconWitness, err := serialize.FromJsonArkProof(arkProof)

				if err != nil {
					log.Fatal(err)
					return nil, nil, nil, err
				}
				reconVk, err := serialize.FromJsonArkVK(arkVk)
				if err != nil {
					log.Fatal(err)
					return nil, nil, nil, err
				}
				err = groth16_bls12381.Verify(reconArkProof, blsVk, reconWitness)
				if err != nil {

					log.Fatal(err)
					return nil, nil, nil, err
				} else {
					log.Default().Println("proof verified ok")
				}
				err = groth16_bls12381.Verify(reconArkProof, reconVk, reconWitness)

				if err != nil {
					log.Fatal(err)
					return nil, nil, nil, err
				}*/
		return blsProof, blsVk, blsWitness, nil
	}
}
