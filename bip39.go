package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
)

// NewEntropy ...
func NewEntropy() ([]byte, error) {
	entropy := make([]byte, 256/8)
	_, _ = rand.Read(entropy)

	return entropy, nil
}

// NewMnemonic ...
func NewMnemonic(entropy []byte) (string, error) {
	wordlist := GetWordlist()

	// length of entropy in bits
	entropyBitLen := len(entropy) * 8
	// checksum length in bits
	checksumBitLen := entropyBitLen / 32
	// how long the mnemonic sentence will be in words
	sentenceLen := (entropyBitLen + checksumBitLen) / 11
	// add the checksum to our entropy
	entropy = addChecksum(entropy)

	/*
		Algo:
		1. Break the entropy up into sections of 11
		bits
		2. "&" mask the rightmost section
		3. Convert section to decimal
		4. Find word at that index
		5. bitshift entropy 11 bits to the right
		6. Write word to the end of array
	*/

	entropyInt := new(big.Int).SetBytes(entropy)
	words := make([]string, sentenceLen)
	word := big.NewInt(0)

	for i := sentenceLen - 1; i >= 0; i-- {
		word.And(entropyInt, big.NewInt(2047))
		wordBytes := padSlice(word.Bytes(), 2)
		wInd := binary.BigEndian.Uint16(wordBytes)
		words[i] = wordlist[wInd]
	}

	return strings.Join(words, " "), nil

}

func addChecksum(entropy []byte) []byte {
	hasher := sha256.New()
	_, _ = hasher.Write(entropy) // error is nil
	hash := hasher.Sum(nil)
	firstChecksumByte := hash[0]

	checksumBitLen := uint(len(entropy) / 4)

	dataBigInt := new(big.Int).SetBytes(entropy)

	for i := uint(0); i < checksumBitLen; i++ {
		// bitshift to the left
		dataBigInt.Mul(dataBigInt, big.NewInt(2))
		if firstChecksumByte&(1<<(7-i)) > 0 {
			dataBigInt.Or(dataBigInt, big.NewInt(1))
		}
	}
	return dataBigInt.Bytes()
}

func padSlice(data []byte, paddingLen int) []byte {
	diff := paddingLen - len(data)
	if diff <= 0 {
		return data
	}

	slice := make([]byte, paddingLen)
	copy(slice[diff:], data)
	return slice
}

func main() {
	entropy, _ := NewEntropy()
	mnemonic, _ := NewMnemonic(entropy)
	fmt.Printf("%s", mnemonic)
}
