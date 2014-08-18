package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/cespare/matasano"
	"github.com/cespare/matasano/p13"
	"github.com/cespare/matasano/pkcs7"
)

func Problem9() (string, error) {
	const (
		block    = "YELLOW SUBMARINE"
		expected = "YELLOW SUBMARINE\x04\x04\x04\x04"
	)
	padded := pkcs7.Pad([]byte(block), 20)
	if string(padded) != expected {
		return "", fmt.Errorf("the padded buffer did not match the expected value")
	}
	unpadded, err := pkcs7.Unpad(padded)
	if err != nil {
		return "", err
	}
	if string(unpadded) == block {
		return "OK", nil
	}
	return "", fmt.Errorf("the unpadded buffer did not match the expected value")
}

func Problem10() (string, error) {
	const (
		filename = "files/problem10.txt"
		key      = "YELLOW SUBMARINE"
	)
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	b64 := base64.NewDecoder(base64.StdEncoding, f)
	encrypted, err := ioutil.ReadAll(b64)
	if err != nil {
		return "", err
	}

	iv := make([]byte, 16)
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	decrypted := make([]byte, len(encrypted))
	decrypter := matasano.NewCBCDecrypter(cipher, iv)
	decrypter.CryptBlocks(decrypted, encrypted)

	newEncrypted := make([]byte, len(decrypted))
	encrypter := matasano.NewCBCEncrypter(cipher, iv)
	encrypter.CryptBlocks(newEncrypted, decrypted)

	if !bytes.Equal(encrypted, newEncrypted) {
		return "", fmt.Errorf("re-encrypted message does not match original")
	}
	return fmt.Sprintf("Message: %q", decrypted), nil
}

// I simply call the oracle function with a large input of 0-value bytes (0x0 0x0 ...) and check whether some
// of the interior blocks of the encrypted result are the same.
func Problem11() (string, error) {
	const trials = 100
	success := 0
	input := make([]byte, 160)
	for i := 0; i < trials; i++ {
		encrypted, err, ecb := matasano.AESOracle(input)
		if err != nil {
			return "", err
		}
		if matasano.IsECB(encrypted, 16) == ecb {
			success++
		}
	}
	msg := fmt.Sprintf("ECB correctly detected %d out of %d times", success, trials)
	if success == trials {
		return msg, nil
	}
	return "", fmt.Errorf(msg)
}

func Problem12() (string, error) {
	const ciphertextBase64 = `
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
`
	ciphertext, err := matasano.Base64ToBytes(ciphertextBase64)
	if err != nil {
		return "", err
	}
	oracle := matasano.NewAESOracle2(ciphertext)

	// First, determine the block size. Just feed in larger and larger input until the encrypted size jumps up.
	// The difference is the block size.
	blockSize, err := matasano.DetermineBlockSize(oracle)
	if err != nil {
		return "", err
	}

	// Confirm that the oracle is emitting ECB encrypted data.
	input := make([]byte, blockSize*10)
	encrypted, err := oracle.Encrypt(input)
	if err != nil {
		return "", err
	}
	if !matasano.IsECB(encrypted, blockSize) {
		return "", fmt.Errorf("ECB not detected")
	}

	// Determine the length of the unknown string.
	encrypted, err = oracle.Encrypt(nil)
	if err != nil {
		return "", err
	}
	unknownLength := len(encrypted)

	// Now use determine each byte of the unknown input, starting at the beginning.
	unknown := make([]byte, 0, unknownLength)
	for len(unknown) < unknownLength {
		next, err := oracle.ECBNextUnknownByte(unknown, blockSize)
		if err != nil {
			// At the end, there's an issue because the input is padded. We'll 'discover' that the next byte is
			// 0x1, but then in the next iteration we'll fail to find the subsequent byte because the test input is
			// now padded with 0x2 0x2. We could verify this (keep testing the padding out until we get to
			// unknownLength) but for now I'm not going to bother, and assume that we've decoded the secret message.
			if len(unknown) > unknownLength-blockSize && unknown[len(unknown)-1] == byte(1) {
				unknown = unknown[:len(unknown)-1]
				break
			}
			return "", err
		}
		unknown = append(unknown, next)
	}

	return fmt.Sprintf("Message: %q\n", unknown), nil
}

func Problem13() (string, error) {
	// Could detect the block size and ECB as in #12, but going to skip that this time.
	const blockSize = 16

	// Strategy: our final string will have N blocks such that the last two blocks look like:
	// N-2: [...........role=]
	// N-1: [admin....pad....]
	// We can do this with three blocks by using an email address that's 13 bytes long:
	// 1: email=abc@defgh.
	// 2: com&uid=10&role=
	// 3: admin...........   (all the . are 0xb)
	// So we need to separately determine what each of the encrypted values of those blocks are. The first 2 are
	// the same as if we just call EncryptedProfileFor(abc@defgh.com); we'll use a specially constructed email
	// address to determine the value of the last block:
	// 1: email=aaaaaaaaaa
	// 2: admin...........    . = 0xb
	// 3: @whatever.com

	target := make([]byte, blockSize*3)
	first, err := p13.EncryptedProfileFor("abc@defgh.com")
	if err != nil {
		return "", err
	}
	copy(target, first[:blockSize*2])

	second, err := p13.EncryptedProfileFor("aaaaaaaaaaadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b")
	if err != nil {
		return "", err
	}
	copy(target[2*blockSize:], second[blockSize:2*blockSize])

	result, err := p13.DecryptProfile(target)
	if err != nil {
		return "", err
	}
	role := result.Get("role")
	msg := fmt.Sprintf("role: %q", role)
	if role == "admin" {
		return msg, nil
	}
	return "", fmt.Errorf(msg)
}

func Problem14() (string, error) {
	const ciphertextBase64 = `
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
`
	ciphertext, err := matasano.Base64ToBytes(ciphertextBase64)
	if err != nil {
		return "", err
	}
	oracle := matasano.NewAESOracle3(ciphertext)

	// Determine block size
	blockSize, err := matasano.DetermineBlockSize(oracle)
	if err != nil {
		return "", err
	}

	// Confirm that the oracle is emitting ECB encrypted data.
	input := make([]byte, blockSize*10)
	encrypted, err := oracle.Encrypt(input)
	if err != nil {
		return "", err
	}
	if !matasano.IsECB(encrypted, blockSize) {
		return "", fmt.Errorf("ECB not detected")
	}



	return "OK", nil

	//// Now use determine each byte of the unknown input, starting at the beginning.
	//unknown := make([]byte, 0, unknownLength)
	//for len(unknown) < unknownLength {
	//next, err := oracle.ECBNextUnknownByte(unknown, blockSize)
	//if err != nil {
	//// At the end, there's an issue because the input is padded. We'll 'discover' that the next byte is
	//// 0x1, but then in the next iteration we'll fail to find the subsequent byte because the test input is
	//// now padded with 0x2 0x2. We could verify this (keep testing the padding out until we get to
	//// unknownLength) but for now I'm not going to bother, and assume that we've decoded the secret message.
	//if len(unknown) > unknownLength-blockSize && unknown[len(unknown)-1] == byte(1) {
	//unknown = unknown[:len(unknown)-1]
	//break
	//}
	//return "", err
	//}
	//unknown = append(unknown, next)
	//}

	//return fmt.Sprintf("Message: %q\n", unknown), nil
}
