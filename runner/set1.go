package main

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"strings"

	"github.com/cespare/matasano"
	"github.com/cespare/matasano/xorcipher"
)

const (
	corpusFilename = "files/the_adventures_of_sherlock_holmes.txt"
)

var xorCorpus *xorcipher.Corpus

func init() {
	var err error
	xorCorpus, err = xorcipher.NewCorpus(corpusFilename)
	if err != nil {
		panic(err)
	}
}

func Problem1() (string, error) {
	const (
		hex    = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	)

	b, err := matasano.HexToBytes(hex)
	if err != nil {
		return "", err
	}
	result := matasano.BytesToBase64(b)
	if result == base64 {
		return "OK", nil
	} else {
		return "", fmt.Errorf("base64 result did not match")
	}
}

func Problem2() (string, error) {
	const (
		s1       = "1c0111001f010100061a024b53535009181c"
		s2       = "686974207468652062756c6c277320657965"
		expected = "746865206b696420646f6e277420706c6179"
	)

	b1, err := matasano.HexToBytes(s1)
	if err != nil {
		return "", err
	}
	b2, err := matasano.HexToBytes(s2)
	if err != nil {
		return "", err
	}
	result, err := matasano.Xor(b1, b2)
	if err != nil {
		return "", err
	}
	if matasano.BytesToHex(result) != expected {
		return "", fmt.Errorf("result did not match expected")
	}
	return "OK", nil
}

//  First we load a text corpus and record the frequency of each byte's occurrences. The 'diff'
//  (corpus.BuffDiff) is fairly naive -- we'll just sum all the deltas between each byte's frequency in `buf`
//  and that byte's frequency in the corpus. The smaller the diff, the more likely it is that `buf` is English
//  plaintext.
func Problem3() (string, error) {
	const ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	buf, err := matasano.HexToBytes(ciphertext)
	if err != nil {
		return "", err
	}
	decrypted, _, _ := xorCorpus.BestBufScore(buf)
	return fmt.Sprintf("Message: %q", decrypted), nil
}

// Same approach as Problem 3. Just take the best overall score.
func Problem4() (string, error) {
	const filename = "files/problem04.txt"
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		return "", err
	}

	bestScore := math.MaxFloat64
	var bestMsg []byte
	buf := bufio.NewReader(f)
	for {
		hex, err := buf.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			return "", err
		}
		hex = strings.TrimSpace(hex)
		encrypted, err := matasano.HexToBytes(hex)
		if err != nil {
			return "", err
		}
		decrypted, _, score := xorCorpus.BestBufScore(encrypted)
		if score < bestScore {
			bestMsg = decrypted
			bestScore = score
		}
	}
	return fmt.Sprintf("Message: %q", bestMsg), nil
}

func Problem5() (string, error) {
	const (
		plaintext   = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
		key         = "ICE"
		hexSolution = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	)

	text := []byte(plaintext)
	encrypted := make([]byte, len(text))
	matasano.RepeatingKeyXor(encrypted, text, []byte(key))
	hex := matasano.BytesToHex(encrypted)
	if hex != hexSolution {
		return "", fmt.Errorf("encrypted string doesn't match")
	}
	return "OK", nil
}

// Just follow the steps.
func Problem6() (string, error) {
	const filename = "files/problem06.txt"
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		return "", err
	}
	decoder := base64.NewDecoder(base64.StdEncoding, f)
	encrypted, err := ioutil.ReadAll(decoder)
	if err != nil {
		return "", err
	}

	// First, determine the keysize. We'll take the mean normalized Hamming distance between every consecutive
	// k-block.
	keysize := 0
	lowestAvgHamming := math.MaxFloat64
	for k := 2; k <= 40; k++ {
		var totalNormalizedHamming float64
		count := 0
		for i := 0; i+(k*2) <= len(encrypted); i++ {
			h := matasano.Hamming(encrypted[i:i+k], encrypted[i+k:i+(2*k)])
			totalNormalizedHamming += (float64(h) / float64(k))
			count++
		}
		d := totalNormalizedHamming / float64(count)
		if d < lowestAvgHamming {
			lowestAvgHamming = d
			keysize = k
		}
	}

	// Next, use our function from #3 to determine the key byte for each position of the blocks.
	key := []byte{}
	for offset := 0; offset < keysize; offset++ {
		transposed := []byte{}
		for i := offset; i < len(encrypted); i += keysize {
			transposed = append(transposed, encrypted[i])
		}
		_, c, _ := xorCorpus.BestBufScore(transposed)
		key = append(key, c)
	}

	// Now use the key to decrypt the message using the function from #5.
	decrypted := make([]byte, len(encrypted))
	matasano.RepeatingKeyXor(decrypted, encrypted, key)

	return fmt.Sprintf("Message: %q\n", decrypted), nil
}

func Problem7() (string, error) {
	const (
		filename = "files/problem07.txt"
		key      = "YELLOW SUBMARINE"
	)
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		return "", err
	}

	buf := base64.NewDecoder(base64.StdEncoding, f)
	encrypted, err := ioutil.ReadAll(buf)
	if err != nil {
		return "", err
	}

	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	decrypted := make([]byte, len(encrypted))
	decrypter := matasano.NewECBDecrypter(cipher)
	decrypter.CryptBlocks(decrypted, encrypted)

	return fmt.Sprintf("Message: %q\n", decrypted), nil
}

// I wasn't really sure what to do here. The only thing I could think of was to check for repeated 16-byte
// chunks, but this depends on the plaintext containing repeated 16-byte segments as well which doesn't seem
// particularly likely in normal English text. But this appeared to be the correct approach because only one
// of the 204 lines met this criterion.
func Problem8() (string, error) {
	const filename = "files/problem08.txt"
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		return "", err
	}
	buf := bufio.NewReader(f)
	ciphertexts := [][]byte{}
	for {
		line, err := buf.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			return "", err
		}
		encrypted, err := matasano.HexToBytes(strings.TrimSpace(line))
		if err != nil {
			return "", err
		}
		ciphertexts = append(ciphertexts, encrypted)
	}

	possibleEcb := []int{}

	for i, encrypted := range ciphertexts {
		seen := make(map[[16]byte]int)
		if len(encrypted)%16 != 0 {
			return "", fmt.Errorf("expected encrypted texts to have lengths a multiple of 16")
		}
		for len(encrypted) > 0 {
			var block [16]byte
			for j := range block {
				block[j] = encrypted[j]
			}
			encrypted = encrypted[16:]
			seen[block]++
		}
		for _, count := range seen {
			if count > 1 {
				possibleEcb = append(possibleEcb, i)
				break
			}
		}
	}

	switch len(possibleEcb) {
	case 0:
		return "", fmt.Errorf("no ECB ciphertexts detected")
	case 1:
		return fmt.Sprintf("ECB ciphertext detected at index %d", possibleEcb[0]), nil
	}
	return "", fmt.Errorf("multiple ECB ciphertexts detected; cannot distinguish")
}
