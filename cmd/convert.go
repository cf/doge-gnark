package cmd

import (
	"github.com/GopherJ/doge-covenant/serialize"
	"fmt"

	"github.com/spf13/cobra"
)

var convertFromFormat string
var convertToFormat string

func init() {
	convertCmd.Flags().StringVarP(&convertFromFormat, "from", "f", "", "Input format type (ark|arkhex|arkhex2|circom)")
	convertCmd.Flags().StringVarP(&convertToFormat, "to", "t", "", "Output format type (ark|arkhex|arkhex2|circom)")

	rootCmd.AddCommand(convertCmd)
}
func runConvertFile(fileType string, fromFormat serialize.ProofSerializationFormat, toFormat serialize.ProofSerializationFormat, inputFile string, outputFile string) error {

	if fileType == "proof" {
		proof, witness, err := serialize.LoadProof(inputFile, fromFormat)
		if err != nil {
			return err
		}
		err = serialize.SaveProof(proof, witness, toFormat, outputFile)
		if err != nil {
			return err
		}
	} else if fileType == "vk" {
		vk, err := serialize.LoadVK(inputFile, fromFormat)
		if err != nil {
			return err
		}
		err = serialize.SaveVK(vk, toFormat, outputFile)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("unknown file type %s", fileType)
	}
	return nil
}

var convertCmd = &cobra.Command{
	Use:   "convert <vk|proof|vkproof> --from <ark|arkhex2|circom> --to <ark|arkhex2|circom> <input file> <output file>",
	Short: "Generate a BitIDE verifier script for a proof/vk",
	Long:  `Generate a BitIDE verifier script for a proof/vk`,
	Args:  cobra.MinimumNArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		fromFormat := serialize.ProofSerializationFormatFromString(convertFromFormat)
		if fromFormat == serialize.Unknown {
			return fmt.Errorf("unknown from format %s", convertFromFormat)
		}
		toFormat := serialize.ProofSerializationFormatFromString(convertToFormat)
		if toFormat == serialize.Unknown {
			return fmt.Errorf("unknown to format %s", convertToFormat)
		}
		fileType := args[0]
		inputFile := args[1]
		outputFile := args[2]
		if fileType == "proof" || fileType == "vk" {
			return runConvertFile(fileType, fromFormat, toFormat, inputFile, outputFile)
		} else if fileType == "vkproof" {
			if len(args) != 5 {
				return fmt.Errorf("expected 5 arguments for vkproof input")
			}
			err := runConvertFile("vk", fromFormat, toFormat, inputFile, outputFile)
			if err != nil {
				return err
			}
			return runConvertFile("proof", fromFormat, toFormat, args[3], args[4])
		} else {
			return fmt.Errorf("unknown file type %s", fileType)
		}
	},
}
