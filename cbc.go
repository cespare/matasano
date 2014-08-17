package matasano

import "crypto/cipher"

// There is already a CBC BlockMode implementation in the crypto/cipher package, but in the interest of not
// "cheating" I'll implement this myself from scratch. (But I read the stdlib implemenation of CBC mode when I
// was implementing ECB earlier, so mine looks similar to that.)

type cbc struct {
	b         cipher.Block
	blockSize int
	iv        []byte
	tmp       []byte
	tmp2      []byte
}

func newCbc(b cipher.Block, iv []byte) *cbc {
	c := &cbc{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        iv,
		tmp:       make([]byte, b.BlockSize()),
		tmp2:      make([]byte, b.BlockSize()),
	}
	if c.blockSize != len(c.iv) {
		panic("IV must have length equal to blocksize.")
	}
	return c
}

type cbcEncrypter cbc
type cbcDecrypter cbc

func NewCBCEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	return (*cbcEncrypter)(newCbc(b, iv))
}
func NewCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	return (*cbcDecrypter)(newCbc(b, iv))
}

func (e *cbcEncrypter) BlockSize() int { return e.blockSize }
func (d *cbcDecrypter) BlockSize() int { return d.blockSize }

func (e *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("Source size must be a multiple of block size.")
	}
	copy(e.tmp, e.iv)
	for len(src) > 0 {
		for i := 0; i < e.blockSize; i++ {
			e.tmp[i] ^= src[i]
		}
		e.b.Encrypt(e.tmp, e.tmp)
		for i := 0; i < e.blockSize; i++ {
			dst[i] = e.tmp[i]
		}
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
}

func (d *cbcDecrypter) CryptBlocks(dst, src []byte) {
	copy(d.tmp2, d.iv)
	for len(src) > 0 {
		d.b.Decrypt(d.tmp, src[:d.blockSize])
		for i := 0; i < d.blockSize; i++ {
			d.tmp[i] ^= d.tmp2[i]
		}
		copy(d.tmp2, src[:d.blockSize])
		copy(dst[:d.blockSize], d.tmp)
		src = src[d.blockSize:]
		dst = dst[d.blockSize:]
	}
}
