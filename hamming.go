package matasano

func Hamming(b1, b2 []byte) int {
	if len(b1) != len(b2) {
		panic("the Hamming distance is only defined for buffers of equal length")
	}
	// NOTE: This is probably the simplest way to count set bits. There are many faster, bit-twiddly methods
	// listed here: http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetNaive
	count := 0
	for i, b := range b1 {
		for x := b ^ b2[i]; x > 0; x >>= 1 {
			count += int(x & 1)
		}
	}
	return count
}
