package matasano

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/rand"
)

func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

func HexToBytes(h string) ([]byte, error) {
	return hex.DecodeString(h)
}

func BytesToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func Base64ToBytes(b64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b64)
}

func Xor(buf1, buf2 []byte) ([]byte, error) {
	if len(buf1) != len(buf2) {
		return nil, errors.New("Buffers must be equal length.")
	}
	result := make([]byte, len(buf1))
	for i, b1 := range buf1 {
		result[i] = b1 ^ buf2[i]
	}
	return result, nil
}

func RandomSlice(length int) []byte {
	random := make([]byte, length)
	for i := range random {
		random[i] = byte(rand.Intn(256))
	}
	return random
}
