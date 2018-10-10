package sign

import (
	"encoding/hex"
	"libsodium-server/sodium"
	"log"
	"testing"
	"github.com/stretchr/testify/assert"
)

var publicKey []byte
var secretKey []byte

func init() {
	var err error = nil

	publicKey, err = hex.DecodeString("4eea077c7ff9a0a682d0b85ba9526b65841c91af733c1b5955f475c33db5e5c2")

	if err != nil {
		log.Fatalf("Failed to initialize: %v", err)
	}

	secretKey, err = hex.DecodeString("926123ce01ed1d918d29454cd391bd9e74e9e88ffadb387316593cbbfd3104b74eea077c7ff9a0a682d0b85ba9526b65841c91af733c1b5955f475c33db5e5c2")

	if err != nil {
		log.Fatalf("Failed to initialize: %v", err)
	}
	sodium.Init()
}

func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	assert.Nil(t, err)
	assert.Len(t, keyPair.PublicKey, 32)
	assert.Len(t, keyPair.SecretKey, 64)
}

func TestDetached(t *testing.T) {
	expected := "f3d7aad8b006b950b154424f1a5c54bf2e6ee8ea35f864b2f5c2519604e2feab1c47d505d0e371147a09e25ae2cd22fc913273e0028b0298c0603a495096780a"
	message, _ := hex.DecodeString("7323ec7a8e309a5e0d672e7e4aa6647a5f08859501e7b9f0a91ccc80d41e342a3da9513f30fe22b5c8466c9378498cf2486d2fb0e98663a8f27a20c401304801")

	digest, err := Detached(message, secretKey)
	assert.Nil(t, err)
	assert.Len(t, digest, 64)
	assert.Equal(t, expected, hex.EncodeToString(digest))
}

func TestVerify(t *testing.T) {
	message := []byte("Hello, libsodium")
	signature, _ := hex.DecodeString("3e79c8ff9f6e2cbd242f8ddb9afd729c30e2510eec446323e756a7a5419742b18425d7021ab935c878505b060c228f82e5961722e57b0012855c0349d6196f0a")

	match, err := Verify(message, signature, publicKey)
	assert.Nil(t, err)
	assert.True(t, match)
}

func TestHashGeneric(t *testing.T) {
	message := []byte("Hello, libsodium")
	signature, _ := hex.DecodeString("6ae897b5ae2a62bcc5844220e93958c7e7806eea6e879cb3041aec855b58018b")

	calculated, err := HashGeneric(message)
	assert.Nil(t, err)
	assert.Equal(t, signature, calculated)
}