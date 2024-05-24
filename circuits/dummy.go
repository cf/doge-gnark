package circuits

import (
	"fmt"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/zilong-dai/gnark/backend/groth16"
	groth16_bls12381 "github.com/zilong-dai/gnark/backend/groth16/bls12-381"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

// Circuit y == x**e
// only the bitSize least significant bits of e are used
type dummyCircuit struct {
	// tagging a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`

	E frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
// y == x**e
func (circuit *dummyCircuit) Define(api frontend.API) error {

	// number of bits of exponent

	x_times_y := api.Mul(circuit.X, circuit.Y)
	x_plus_y := api.Add(circuit.X, circuit.Y)

	output := api.Mul(x_times_y, x_plus_y)
	api.AssertIsEqual(circuit.E, output)

	return nil
}

func calcResult(x, y *big.Int) *big.Int {
	left := new(big.Int).Mul(x, y)
	right := new(big.Int).Add(x, y)
	return new(big.Int).Mul(left, right)
}
func ProveDummyCircuitBLSInt(x int, y int) (*groth16_bls12381.Proof, *groth16_bls12381.VerifyingKey, []fr.Element, error) {
	return ProveDummyCircuitBLS(big.NewInt(int64(x)), big.NewInt(int64(y)))

}
func ProveDummyCircuitBLS(x *big.Int, y *big.Int) (*groth16_bls12381.Proof, *groth16_bls12381.VerifyingKey, []fr.Element, error) {

	var circuit dummyCircuit

	// // building the circuit...
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("circuit compilation error")
	}
	fmt.Printf("num pubs: %d\n", ccs.GetNbPublicVariables())

	// create the necessary data for KZG.
	// This is a toy example, normally the trusted setup to build ZKG
	// has been run before.
	// The size of the data in KZG should be the closest power of 2 bounding //
	// above max(nbConstraints, nbVariables).

	// Correct data: the proof passes
	{
		// Witnesses instantiation. Witness is known only by the prover,
		// while public w is a public data known by the verifier.
		var w dummyCircuit

		w.X = x
		w.Y = y
		w.E = calcResult(x, y)

		witnessFull, err := frontend.NewWitness(&w, ecc.BLS12_381.ScalarField())
		if err != nil {
			log.Fatal(err)
			return nil, nil, nil, err
		}

		witnessPublic, err := frontend.NewWitness(&w, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
		if err != nil {
			log.Fatal(err)
			return nil, nil, nil, err
		}

		// public data consists of the polynomials describing the constants involved
		// in the constraints, the polynomial describing the permutation ("grand
		// product argument"), and the FFT domains.

		pk, vk, err := groth16.Setup(ccs)

		//_, err := plonk.Setup(r1cs, kate, &publicWitness)
		if err != nil {
			log.Fatal(err)
			return nil, nil, nil, err
		}
		/*
			vkjson, err := btcsnark.GetVerifyingKeyJsonBls(vk.(*groth16_bls12381.VerifyingKey))
			if err != nil {
				log.Fatal(err)
			}*/
		//fmt.Println("verifying key: ", string(vkjson[:]))
		proof, err := groth16.Prove(ccs, pk, witnessFull)
		if err != nil {
			log.Fatal(err)
			return nil, nil, nil, err
		}

		err = groth16.Verify(proof, vk, witnessPublic)
		if err != nil {
			log.Fatal(err)
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
