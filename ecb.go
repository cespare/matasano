package matasano

import "crypto/cipher"

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb
type ecbDecrypter ecb

func NewECBEncrypter(b cipher.Block) cipher.BlockMode { return (*ecbEncrypter)(newECB(b)) }
func NewECBDecrypter(b cipher.Block) cipher.BlockMode { return (*ecbDecrypter)(newECB(b)) }

func (d *ecbEncrypter) BlockSize() int { return d.blockSize }
func (d *ecbDecrypter) BlockSize() int { return d.blockSize }

func (d *ecbEncrypter) CryptBlocks(dst, src []byte) {
	for len(src) > 0 {
		d.b.Encrypt(dst, src[:d.blockSize])
		src = src[d.blockSize:]
		dst = dst[d.blockSize:]
	}
}

func (d *ecbDecrypter) CryptBlocks(dst, src []byte) {
	for len(src) > 0 {
		d.b.Decrypt(dst, src[:d.blockSize])
		src = src[d.blockSize:]
		dst = dst[d.blockSize:]
	}
}
