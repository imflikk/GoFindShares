package helpers

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"os"
)

// Help from ChatGPT to convert a UTF-16 byte array to a string
func Utf16BytesToString(utf16Bytes []byte) string {
	// Initialize an empty string to store the result
	var str string

	// Iterate over the byte array in pairs (assuming little-endian encoding)
	for i := 0; i < len(utf16Bytes); i += 2 {
		// Read the two bytes as a little-endian UTF-16 code unit
		codeUnit := binary.LittleEndian.Uint16(utf16Bytes[i : i+2])

		// Convert the UTF-16 code unit to a UTF-8 rune and append it to the string
		str += string(codeUnit)
	}

	return str
}

func WriteResultsCSV(path string, results []SearchResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write([]string{"fileLocation", "fileName", "fileSize", "keywordFound", "keywordContext"})
	for _, r := range results {
		w.Write([]string{
			r.FileLocation,
			r.FileName,
			fmt.Sprintf("%d", r.FileSize),
			r.KeywordFound,
			r.KeywordContext,
		})
	}

	return w.Error()
}
