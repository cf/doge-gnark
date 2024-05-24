package cmd

import (
	"github.com/GopherJ/doge-covenant/serialize"
	"fmt"

	groth16 "github.com/zilong-dai/gnark/backend/groth16/bls12-381"
	"github.com/spf13/cobra"
)

var verifyCmdFormat string

//var dummyCommandOutputFile string

func init() {
	verifyCmd.Flags().StringVarP(&verifyCmdFormat, "format", "f", "", "Proof format type (ark|arkhex|circom)")

	rootCmd.AddCommand(verifyCmd)
}

var verifyCmd = &cobra.Command{
	Use:   "verify --format <ark|circom> [output proof.json] [output vk.json]",
	Short: "Verify a proof",
	Long:  `Verify a proof using BLS12-381 curve.`,
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		format := serialize.ProofSerializationFormatFromString(verifyCmdFormat)
		if format == serialize.Unknown {
			return fmt.Errorf("unknown format %s", verifyCmdFormat)
		}
		proof, witness, err := serialize.LoadProof(args[0], format)
		if err != nil {
			return err
		}
		vk, err := serialize.LoadVK(args[1], format)
		if err != nil {
			return err
		}

		err = groth16.Verify(proof, vk, witness)
		if err != nil {
			return err
		}

		return nil
	},
}
