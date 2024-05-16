package serialize

// Weekday - Custom type to hold value for weekday ranging from 1-7
type ProofSerializationFormat int

// Declare related constants for each weekday starting with index 1
const (
	Unknown ProofSerializationFormat = iota     // EnumIndex = 0
	Ark     ProofSerializationFormat = iota + 1 // EnumIndex = 1
	Circom                                      // EnumIndex = 2
	ArkHex                                      // EnumIndex = 3
	ArkHex2                                     // EnumIndex = 4
)

// String - Creating common behavior - give the type a String function
func (w ProofSerializationFormat) String() string {
	return [...]string{"ark", "circom", "arkhex", "arkhex2"}[w-1]
}
func (w ProofSerializationFormat) EnumIndex() int {
	return int(w)
}
func ProofSerializationFormatFromString(s string) ProofSerializationFormat {
	switch s {
	case "ark":
		return Ark
	case "circom":
		return Circom
	case "arkhex":
		return ArkHex
	case "arkhex2":
		return ArkHex2
	}
	return Unknown
}
