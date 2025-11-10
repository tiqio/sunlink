package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	cc "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

type AEADCipher interface {
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
	NonceSize() int
	Overhead() int
}

// secretKey generates a random 256-bit key
func secretKey(password []byte) *[32]byte {
	key := [32]byte{}

	enkey := pbkdf2.Key(password, []byte("easyss-subkey"), 4096, 32, sha256.New)
	copy(key[:], enkey)

	return &key
}

type AEADCipherImpl struct {
	aead  cipher.AEAD
	nonce []byte
}

// Encrypt encrypts data using 256-bit AEAD.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func (aci *AEADCipherImpl) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	if len(aci.nonce) == 0 {
		aci.nonce = make([]byte, aci.aead.NonceSize())
	}

	_, err = io.ReadFull(rand.Reader, aci.nonce)
	if err != nil {
		return nil, err
	}

	return aci.aead.Seal(aci.nonce, aci.nonce, plaintext, nil), nil
}

// Decrypt decrypts data using 256-bit AEAD.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func (aci *AEADCipherImpl) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	if len(ciphertext) < aci.aead.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return aci.aead.Open(nil,
		ciphertext[:aci.aead.NonceSize()],
		ciphertext[aci.aead.NonceSize():],
		nil,
	)
}

// NonceSize return underlying aead nonce size
func (aci *AEADCipherImpl) NonceSize() int {
	return aci.aead.NonceSize()
}

// Overhead return underlying aead overhead size
func (aci *AEADCipherImpl) Overhead() int {
	return aci.aead.Overhead()
}

// NewAes256GCM creates a aes-gcm AEAD instance
func NewAes256GCM(password []byte) (AEADCipher, error) {
	key := secretKey(password)
	block, err := aes.NewCipher((key[:]))
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AEADCipherImpl{aead: aead}, nil
}

// NewChaCha20Poly1305 creates a chacha20-poly1305 AEAD instance
func NewChaCha20Poly1305(password []byte) (AEADCipher, error) {
	key := secretKey(password)
	aead, err := cc.New(key[:])
	if err != nil {
		return nil, err
	}

	return &AEADCipherImpl{aead: aead}, nil
}
