package cmd

import (
	"doge-covenant/circuits"
	"doge-covenant/serialize"
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
)

// var dummyCommandOutputFile string
var simpleCovenantCmdFixedBytesIndex int
var simpleCovenantCmdFixedBytesLength int

// ./doge-covenant provesimplecovenant proof.json vk.json pkey.bin vkey.bin
func init() {
	proveSimpleCovenantCmd.Flags().StringVarP(&dummyCommandOutputFormat, "format", "f", "", "Proof format type (ark|arkhex|circom)")

	proveSimpleCovenantCmd.Flags().IntVarP(&proverKeyFileMode, "mode", "m", 0, "Prover key file mode (0: no file, 1: save file, 2: load file)")
	proveSimpleCovenantCmd.Flags().IntVarP(&simpleCovenantCmdFixedBytesIndex, "index", "i", 0, "Fixed bytes index within your preimage")
	proveSimpleCovenantCmd.Flags().IntVarP(&simpleCovenantCmdFixedBytesLength, "length", "l", 0, "The length of the fixed bytes to constrain")
	rootCmd.AddCommand(proveSimpleCovenantCmd)
}

var proveSimpleCovenantCmd = &cobra.Command{
	Use:   "provesimplecovenant [output proof.json] [output vk.json] [optional: prover key file] [optional: verifier key file] [preimage hex string]",
	Short: "Prove the simple covenant circuit",
	Long:  `Prove the simple covenant circuit using the BLS12-381 curve.`,
	Args:  cobra.MinimumNArgs(3),
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
			if len(args) < 5 {
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
		proof, vk, witness, err := circuits.ProveSimpleCovenantircuit(preImage, proverKeyFileMode, proverKeyFilePath, verifierKeyFilePath, simpleCovenantCmdFixedBytesIndex, preImage[simpleCovenantCmdFixedBytesIndex:(simpleCovenantCmdFixedBytesIndex+simpleCovenantCmdFixedBytesLength)])
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
