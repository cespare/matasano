// Package xorcipher decrypts a single-char XOR cipher.
package xorcipher

import (
	"bufio"
	"io"
	"math"
	"os"
)

type Corpus struct {
	byteFreqs [256]float64
}

func NewCorpus(filename string) (*Corpus, error) {
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		return nil, err
	}
	buf := bufio.NewReader(f)
	var byteCounts [256]int
	var total uint64
	for {
		c, err := buf.ReadByte()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		byteCounts[int(c)]++
		total++
	}
	c := new(Corpus)
	for i := 0; i < 256; i++ {
		c.byteFreqs[i] = float64(byteCounts[i]) / float64(total)
	}
	return c, nil
}

func xorChar(buf []byte, c byte) []byte {
	result := make([]byte, len(buf))
	for i, b := range buf {
		result[i] = b ^ c
	}
	return result
}

// BufDiff creates some measure of the difference in byte distribution between buf and c.
func (c *Corpus) BufDiff(buf []byte) float64 {
	var counts [256]uint64
	for _, b := range buf {
		counts[int(b)]++
	}
	var diff float64
	for i, count := range counts {
		if count == 0 {
			continue
		}
		freq := float64(count) / float64(len(buf))
		diff += math.Abs(freq - c.byteFreqs[i])
	}
	return diff
}

func (c *Corpus) BestBufScore(buf []byte) (result []byte, ch byte, score float64) {
	var (
		decrypted       [256][]byte
		decryptedScores [256]float64
	)
	for i := range decrypted {
		d := xorChar(buf, byte(i))
		decrypted[i] = d
		decryptedScores[i] = c.BufDiff(d)
	}
	best := math.MaxFloat64
	bestIndex := 0
	for i, s := range decryptedScores {
		if s < best {
			best = s
			bestIndex = i
		}
	}
	return decrypted[bestIndex], byte(bestIndex), best
}
