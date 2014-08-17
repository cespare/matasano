package matasano

import (
	"bytes"
	"crypto/aes"
	"errors"
	"math/rand"

	"github.com/cespare/matasano/pkcs7"
)

// AESOracle implements the oracle function described at http://cryptopals.com/sets/2/challenges/11/. It
// returns whether it used ECB so we can check against the detector.
func AESOracle(plaintext []byte) (encrypted []byte, err error, ecb bool) {
	before := RandomSlice(rand.Intn(6) + 5)
	after := RandomSlice(rand.Intn(6) + 5)
	result := make([]byte, len(plaintext)+len(before)+len(after))
	copy(result, before)
	copy(result[len(before):], plaintext)
	copy(result[len(before)+len(plaintext):], after)
	result = pkcs7.Pad(result, 16)

	key := RandomSlice(16)
	iv := RandomSlice(16)
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err, false
	}
	mode := rand.Intn(2)
	encrypter := NewECBEncrypter(cipher)
	if mode == 1 {
		encrypter = NewCBCEncrypter(cipher, iv)
	}

	encrypter.CryptBlocks(result, result)
	return result, nil, (mode == 0)
}

// IsECB implements the ECB detection function described at http://cryptopals.com/sets/2/challenges/11/.
// Assumes that enc is the output of the oracle when the input is many identical bytes.
func IsECB(enc []byte, blockSize int) bool {
	// Check if blocks 3 - 6 are the same (which they should be for ECB).
	if len(enc) < blockSize*6 {
		panic("Not enough input to detect ECB.")
	}
	for j := 0; j < blockSize; j++ {
		baseBlock := 3
		for blockIdx := 4; blockIdx <= 6; blockIdx++ {
			if enc[blockIdx*blockSize+j] != enc[baseBlock*blockSize+j] {
				return false
			}
		}
	}
	return true
}

// AESOracle2 is an instance of the oracle described at http://cryptopals.com/sets/2/challenges/12/.
type AESOracle2 struct {
	ciphertext []byte
	key        []byte
}

func NewAESOracle2(ciphertext []byte) *AESOracle2 {
	return &AESOracle2{ciphertext, RandomSlice(16)}
}

func (o *AESOracle2) Encrypt(plaintext []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(o.key)
	if err != nil {
		return nil, err
	}
	encrypter := NewECBEncrypter(cipher)
	input := make([]byte, len(plaintext)+len(o.ciphertext))
	copy(input, plaintext)
	copy(input[len(plaintext):], o.ciphertext)
	result := pkcs7.Pad(input, 16)
	encrypter.CryptBlocks(result, result)
	return result, nil
}

// ECBNextUnknownByte implements one step of the procedure described at
// http://cryptopals.com/sets/2/challenges/12/.
func (o *AESOracle2) ECBNextUnknownByte(soFar []byte, blockSize int) (byte, error) {
	// Padding with offset bytes at the beginning (using a known byte value of len(soFar) < blockSize) will
	// place exactly one unknown byte at some index (blockSize - 1) (modulo blockSize).
	offset := blockSize - (len(soFar) % blockSize) - 1
	input := make([]byte, offset)   // Use a []byte of all 0x0.
	block := len(soFar) / blockSize // This is the block we care about.
	encrypted, err := o.Encrypt(input)
	if err != nil {
		return 0, err
	}
	targetBlock := encrypted[block*blockSize : (block+1)*blockSize]

	testBlock := make([]byte, blockSize)
	for i := 0; i < blockSize-1; i++ {
		idx := len(soFar) - i - 1
		if idx < 0 {
			testBlock[blockSize-i-2] = byte(0)
		} else {
			testBlock[blockSize-i-2] = soFar[idx]
		}
	}

	for i := 0; i < 256; i++ {
		c := byte(i)
		testBlock[blockSize-1] = c
		enc, err := o.Encrypt(testBlock)
		if err != nil {
			return 0, err
		}
		if bytes.Equal(enc[:blockSize], targetBlock) {
			return c, nil
		}
	}

	return 0, errors.New("could not determine next unknown byte")
}
