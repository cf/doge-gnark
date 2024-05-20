package cmd

import (
	"github.com/GopherJ/doge-covenant/circuits"
	"github.com/GopherJ/doge-covenant/serialize"
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
)

// var dummyCommandOutputFile string
var proverKeyFileMode int

func init() {
	proveSimpleSha256Cmd.Flags().StringVarP(&dummyCommandOutputFormat, "format", "f", "", "Proof format type (ark|arkhex|circom)")

	proveSimpleSha256Cmd.Flags().IntVarP(&proverKeyFileMode, "mode", "m", 0, "Prover key file mode (0: no file, 1: save file, 2: load file)")
	rootCmd.AddCommand(proveSimpleSha256Cmd)
}

var proveSimpleSha256Cmd = &cobra.Command{
	Use:   "provesha256 [output proof.json] [output vk.json] [optional: prover key file] [optional: verifier key file] [optional: preimage hex string]",
	Short: "Prove the simple sha256 circuit",
	Long:  `Prove the simple sha256 circuit using the BLS12-381 curve.`,
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		format := serialize.ProofSerializationFormatFromString(dummyCommandOutputFormat)
		if format == serialize.Unknown {
			return fmt.Errorf("unknown format %s", dummyCommandOutputFormat)
		}
		hexIndex := 2
		proverKeyFilePath := ""
		verifierKeyFilePath := ""

		if proverKeyFileMode != 0 {
			hexIndex = 4
			if len(args) < 4 {
				return fmt.Errorf("prover key file mode is set but no file paths are provided")
			}
			proverKeyFilePath = args[2]
			verifierKeyFilePath = args[3]
		}
		var preImage []byte
		if len(args) > hexIndex {
			preImageA, err := hex.DecodeString(args[hexIndex])
			if err != nil {
				return err
			}
			preImage = preImageA
		} else {
			preImage = []byte("qed for the win")
		}
		if proverKeyFileMode < 0 || proverKeyFileMode > 2 {
			return fmt.Errorf("invalid mode %d", proverKeyFileMode)
		}
		proof, vk, witness, err := circuits.ProveSimpleSha256Circuit(preImage, proverKeyFileMode, proverKeyFilePath, verifierKeyFilePath)
		if err != nil {
			return err
		}
		err = serialize.SaveProof(proof, witness, format, args[0])
		if err != nil {
			return err
		}
		err = serialize.SaveVK(vk, format, args[1])
		if err != nil {
			return err
		}

		return nil
	},
}
