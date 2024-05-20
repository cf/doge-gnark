package cmd

import (
	"github.com/GopherJ/doge-covenant/circuits"
	"github.com/GopherJ/doge-covenant/serialize"
	"fmt"

	"github.com/spf13/cobra"
)

var dummyCommandOutputFormat string

//var dummyCommandOutputFile string

func init() {
	proveDummyCmd.Flags().StringVarP(&dummyCommandOutputFormat, "format", "f", "", "Proof format type (ark|arkhex|circom)")

	rootCmd.AddCommand(proveDummyCmd)
}

var proveDummyCmd = &cobra.Command{
	Use:   "provedummy [output proof.json] [output vk.json]",
	Short: "Prove the example circuit",
	Long:  `Prove the example circuit using the BLS12-381 curve.`,
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		format := serialize.ProofSerializationFormatFromString(dummyCommandOutputFormat)
		if format == serialize.Unknown {
			return fmt.Errorf("unknown format %s", dummyCommandOutputFormat)
		}
		proof, vk, witness, err := circuits.ProveDummyCircuitBLSInt(1337, 7)
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
