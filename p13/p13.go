package p13

import (
	"crypto/aes"
	"fmt"
	"net/url"
	"strings"

	"github.com/cespare/matasano"
	"github.com/cespare/matasano/pkcs7"
)

// Just using net/url for query parsing.

func ProfileFor(email string) string {
	// Using url.Values{...}.Encode() is a bit too robust for my attack to work (low bytes like 0x1 are
	// escaped).
	escapedEmail := strings.NewReplacer("&", "", "=", "").Replace(email)
	return fmt.Sprintf("email=%s&uid=10&role=user", escapedEmail)
}

var key []byte

func init() { key = matasano.RandomSlice(16) }

func EncryptedProfileFor(email string) ([]byte, error) {
	plaintext := ProfileFor(email)
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encrypter := matasano.NewECBEncrypter(cipher)
	result := pkcs7.Pad([]byte(plaintext), 16)
	encrypter.CryptBlocks(result, result)
	return result, nil
}

func DecryptProfile(encrypted []byte) (url.Values, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypter := matasano.NewECBDecrypter(cipher)
	decrypted := make([]byte, len(encrypted))
	decrypter.CryptBlocks(decrypted, encrypted)
	plaintext, err := pkcs7.Unpad(decrypted)
	if err != nil {
		return nil, err
	}
	return url.ParseQuery(string(plaintext))
}
