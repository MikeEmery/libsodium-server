package box

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

	publicKey, err = hex.DecodeString("b5318f6eb1a2d0066a169ea5ed979905abc1ed83a794b87fae52f95cf3e7b100")

	if err != nil {
		log.Fatalf("Failed to initialize: %v", err)
	}

	secretKey, err = hex.DecodeString("60e74ea5be8acb3beec3794930a55287305916b0c7385ad3bc6e54011ae7d5e6")

	if err != nil {
		log.Fatalf("Failed to initialize: %v", err)
	}
	sodium.Init()
}

func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	assert.Nil(t, err)
	assert.Len(t, keyPair.PublicKey, 32)
	assert.Len(t, keyPair.SecretKey, 32)
}

func TestSealAndOpen(t *testing.T) {
	str := "Super duper secret"
	msg := []byte(str)
	ciphertext, err := Seal(msg, publicKey)

	assert.Nil(t, err)

	plaintext, err := SealOpen(ciphertext, KeyPair{ PublicKey: publicKey, SecretKey: secretKey })
	assert.Nil(t, err)
	assert.Equal(t, str, string(plaintext))
}

func TestEasyAndOpen(t *testing.T) {
	keyPair, err := GenerateKeyPair()

	str := "Super duper secret"
	msg := []byte(str)
	easyResult, err := Easy(msg, keyPair.SecretKey, publicKey)

	assert.Nil(t, err)
	assert.NotNil(t, easyResult)

	plaintext, err := EasyOpen(easyResult, keyPair.PublicKey, secretKey)

	assert.Nil(t, err)
	assert.Equal(t, str, string(plaintext))
}