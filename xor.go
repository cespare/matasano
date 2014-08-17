package matasano

func RepeatingKeyXor(dst, src, key []byte) {
	for i, b := range src {
		dst[i] = b ^ key[i%len(key)]
	}
}
