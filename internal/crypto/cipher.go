// Package crypto provides AES-256-GCM encryption for placeholder mappings and memory storage.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

// Encryptor handles AES-256-GCM encryption operations.
type Encryptor struct {
	key []byte
}

// NewEncryptor creates an Encryptor from a 32-byte key or derives one from a passphrase.
// Passphrase must be at least 16 characters for security.
func NewEncryptor(keyMaterial []byte) *Encryptor {
	if len(keyMaterial) == 32 {
		return &Encryptor{key: keyMaterial}
	}

	// Derive a 32-byte key using SHA-256
	h := sha256.Sum256(keyMaterial)
	return &Encryptor{key: h[:]}
}

// Encrypt encrypts plaintext using AES-256-GCM.
// Returns base64-encoded ciphertext.
func (e *Encryptor) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded AES-256-GCM ciphertext.
func (e *Encryptor) Decrypt(encoded string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptString encrypts a string and returns base64-encoded result.
func (e *Encryptor) EncryptString(s string) (string, error) {
	return e.Encrypt([]byte(s))
}

// DecryptString decrypts a base64-encoded ciphertext to string.
func (e *Encryptor) DecryptString(encoded string) (string, error) {
	b, err := e.Decrypt(encoded)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// GenerateKey generates a cryptographically random 32-byte key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// KeyFromPassphrase derives a 32-byte key from a passphrase using SHA-256.
func KeyFromPassphrase(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}
