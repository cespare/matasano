// Package pkcs7 implements PKCS#7 padding. See http://www.ietf.org/rfc/rfc2315.txt.
package pkcs7

import "errors"

func Pad(buf []byte, size int) []byte {
	if size < 2 {
		panic("Bad block size for PKCS#7 padding.")
	}
	n := size - (len(buf) % size)
	result := make([]byte, len(buf)+n)
	copy(result, buf)
	for i := len(buf); i < len(result); i++ {
		result[i] = byte(n)
	}
	return result
}

func Unpad(buf []byte) ([]byte, error) {
	err := errors.New("Input is not a PKCS#7 padded block.")
	if len(buf) == 0 {
		return nil, err
	}
	c := buf[len(buf)-1]
	n := int(c)
	if n > len(buf) {
		return nil, err
	}
	for i := len(buf) - n; i < len(buf); i++ {
		if buf[i] != c {
			return nil, err
		}
	}
	return buf[:len(buf)-n], nil
}
