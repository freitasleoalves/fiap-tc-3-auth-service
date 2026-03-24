package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateAPIKey(t *testing.T) {
	key, err := generateAPIKey()
	if err != nil {
		t.Fatalf("generateAPIKey() retornou erro: %v", err)
	}

	if !strings.HasPrefix(key, "tm_key_") {
		t.Errorf("chave deveria ter prefixo 'tm_key_', got: %s", key)
	}

	// tm_key_ (7 chars) + 64 hex chars (32 bytes) = 71 chars
	if len(key) != 71 {
		t.Errorf("chave deveria ter 71 caracteres, got: %d", len(key))
	}
}

func TestGenerateAPIKeyUniqueness(t *testing.T) {
	key1, _ := generateAPIKey()
	key2, _ := generateAPIKey()

	if key1 == key2 {
		t.Error("duas chaves geradas não deveriam ser iguais")
	}
}

func TestHashAPIKey(t *testing.T) {
	key := "tm_key_abc123"
	hash := hashAPIKey(key)

	// Deve ser hex SHA-256 (64 chars)
	if len(hash) != 64 {
		t.Errorf("hash deveria ter 64 caracteres, got: %d", len(hash))
	}

	// Deve ser determinístico
	hash2 := hashAPIKey(key)
	if hash != hash2 {
		t.Error("hashAPIKey deveria ser determinístico")
	}

	// Verifica manualmente
	expected := sha256.Sum256([]byte(key))
	expectedHex := hex.EncodeToString(expected[:])
	if hash != expectedHex {
		t.Errorf("hash esperado %s, got %s", expectedHex, hash)
	}
}

func TestHashAPIKeyDifferentInputs(t *testing.T) {
	hash1 := hashAPIKey("key1")
	hash2 := hashAPIKey("key2")

	if hash1 == hash2 {
		t.Error("chaves diferentes deveriam produzir hashes diferentes")
	}
}
