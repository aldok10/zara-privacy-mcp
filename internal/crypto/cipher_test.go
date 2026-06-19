package crypto

import (
	"strings"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		plaintext string
	}{
		{name: "standard key", key: []byte("test-key-32-bytes-long-minimum!!"), plaintext: "hello secret world"},
		{name: "short passphrase", key: []byte("short"), plaintext: "test data with short key"},
		{name: "empty plaintext", key: []byte("test-key-32-bytes-long-minimum!!"), plaintext: ""},
		{name: "unicode text", key: []byte("unicode-key-32-bytes-long-test!!"), plaintext: "emoji: 🔒 and kanji: 暗号"},
		{name: "long text", key: []byte("long-key-32-bytes-long-minimum!!"), plaintext: strings.Repeat("a", 10000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewEncryptor(tt.key)

			encrypted, err := enc.EncryptString(tt.plaintext)
			if err != nil {
				t.Fatalf("EncryptString() error = %v", err)
			}
			if encrypted == tt.plaintext && tt.plaintext != "" {
				t.Error("encrypted should differ from plaintext")
			}

			decrypted, err := enc.DecryptString(encrypted)
			if err != nil {
				t.Fatalf("DecryptString() error = %v", err)
			}
			if decrypted != tt.plaintext {
				t.Errorf("roundtrip failed: got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncryptDecrypt_Binary(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "null bytes", data: []byte{0x00, 0x00, 0x00}},
		{name: "all values", data: []byte{0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF}},
		{name: "empty", data: []byte{}},
	}

	enc := NewEncryptor([]byte("binary-key-32-bytes-long-test!!!"))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := enc.Encrypt(tt.data)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			decrypted, err := enc.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}
			if string(decrypted) != string(tt.data) {
				t.Errorf("binary roundtrip failed")
			}
		})
	}
}

func TestDecrypt_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		ciphertext string
	}{
		{name: "not base64", ciphertext: "not-valid!!!"},
		{name: "too short", ciphertext: "YQ=="},
		{name: "empty", ciphertext: ""},
		{name: "corrupted", ciphertext: "dGVzdA=="},
	}

	enc := NewEncryptor([]byte("test-key-32-bytes-long-minimum!!"))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := enc.DecryptString(tt.ciphertext)
			if err == nil {
				t.Error("expected error for invalid ciphertext")
			}
		})
	}
}

func TestKeyFromPassphrase(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
	}{
		{name: "short", passphrase: "abc"},
		{name: "standard", passphrase: "my-secret-passphrase-for-encryption"},
		{name: "empty", passphrase: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := KeyFromPassphrase(tt.passphrase)
			if len(key) != 32 {
				t.Errorf("KeyFromPassphrase(%q) len = %d; want 32", tt.passphrase, len(key))
			}
			// Deterministic
			if string(KeyFromPassphrase(tt.passphrase)) != string(key) {
				t.Error("same passphrase should produce same key")
			}
		})
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Errorf("GenerateKey() len = %d; want 32", len(key))
	}

	// Should be random (different each time)
	key2, _ := GenerateKey()
	if string(key) == string(key2) {
		t.Error("GenerateKey() should produce unique keys")
	}
}
