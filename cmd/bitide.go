package cmd

import (
	"github.com/GopherJ/doge-covenant/btcprint"
	"github.com/GopherJ/doge-covenant/serialize"
	"fmt"
	"log"

	groth16 "github.com/zilong-dai/gnark/backend/groth16/bls12-381"
	"github.com/spf13/cobra"
)

//var dummyCommandOutputFile string

func init() {
	bitIdeCmd.Flags().StringVarP(&verifyCmdFormat, "format", "f", "", "Proof format type (ark|arkhex|arkhex2|circom)")

	rootCmd.AddCommand(bitIdeCmd)
}

var bitIdeCmd = &cobra.Command{
	Use:   "bitide --format <ark|arkhex2|circom> <input proof.json> <output vk.json>",
	Short: "Generate a BitIDE verifier script for a proof/vk",
	Long:  `Generate a BitIDE verifier script for a proof/vk`,
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
		arkProof := serialize.ToJsonArkProof(proof, witness)
		arkVk := serialize.ToJsonArkVK(vk)

		arkHex2Proof := arkProof.ToArkHex2Proof()
		arkHex2Vk := arkVk.ToArkHex2VK()
		proofStr, err := btcprint.PrintArkHex2Proof(arkHex2Proof)
		if err != nil {
			return err
		}
		vkStr, err := btcprint.PrintArkHex2VK(arkHex2Vk)
		if err != nil {
			return err
		}

		log.Printf(`
  // Proof Data (256-bytes)
  %s
  b.END_EXAMPLE_WITNESS();
  // Circuit Specific Verifier Data (480-bytes serialized as 6 80-byte chunks)
  %s
  b.constant(0).tag(\"mode\");
  b.OP_CHECKGROTH16VERIFY();
  // stack is not modified so as to preserve compatibility with older versions of dogecoin
  b.OP_2DROP();
  b.OP_2DROP();
  b.OP_2DROP();
  b.OP_2DROP();
  b.OP_2DROP();
  b.OP_2DROP();
  b.OP_DROP();
  b.OP_1();
"`, proofStr, vkStr)

		err = groth16.Verify(proof, vk, witness)
		if err != nil {
			return err
		}

		return nil
	},
}
