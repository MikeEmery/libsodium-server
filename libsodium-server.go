package main

import "C"
import (
	"bufio"
	"os"
	logger "log"
	"encoding/binary"
	"libsodium-server/sodium"
	"github.com/golang/protobuf/proto"
	"libsodium-server/box"
	"io"
	"libsodium-server/sign"
)

var log *logger.Logger

func init() {
	log = logger.New(os.Stderr, "libsodium: ", 0)
}

func generateBoxKeyPair() *sodium.Response {
	keyPair, err := box.GenerateKeyPair()

	if err != nil {
		return buildSodiumResponseError(sodium.Error_ERROR_OPERATION_FAILED)
	}

	response := &sodium.BoxKeyPairGenerateResponse{
		KeyPair: &sodium.KeyPair{
			PublicKey: keyPair.PublicKey,
			SecretKey: keyPair.SecretKey,
		},
	}

	return &sodium.Response{
		SodiumResult: &sodium.Response_BoxKeyPairGenerateResponse{ BoxKeyPairGenerateResponse: response },
	}
}

func readIncomingRequest(reader *bufio.Reader) (*sodium.Request, error) {
	var header = make([]byte, 4)
	count, err := reader.Read(header)

	if err != nil {
		return nil, err
	} else if count == 0 {
		return nil, io.EOF
	}

	size := int(binary.BigEndian.Uint32(header))
	buf := make([]byte, size)
	count, err = reader.Read(buf)

	if err != nil {
		return nil, err
	} else if count == 0 {
		return nil, io.EOF
	}

	var request = &sodium.Request{}
	err = proto.Unmarshal(buf, request)

	return request, err
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)

	for {
		request, err := readIncomingRequest(reader)

		if err == io.EOF {
			log.Printf("End of stream")
			break
		} else if err != nil {
			log.Printf("Error %v", err)
			continue
		}

		wireResponse := handleRequest(request)
		writeResponse(writer, wireResponse)
	}
}

func writeResponse(writer *bufio.Writer, response *sodium.Response) error {
	buf, _ := proto.Marshal(response)
	outHeader := make([]byte, 4)
	binary.BigEndian.PutUint32(outHeader, uint32(len(buf)))

	writer.Write(outHeader)
	writer.Write(buf)
	writer.Flush()
}

func handleRequest(request *sodium.Request) *sodium.Response {
	var wireResponse *sodium.Response

	switch op := request.SodiumOperation.(type) {
	case *sodium.Request_BoxEasyRequest:
		log.Printf("BoxEasyRequest")
		wireResponse = encryptBoxEasy(
			op.BoxEasyRequest.Plaintext,
			op.BoxEasyRequest.SecretKey,
			op.BoxEasyRequest.PublicKey)
	case *sodium.Request_BoxEasyOpenRequest:
		log.Printf("BoxEasyOpenRequest")
		wireResponse = decryptBoxEasy(
			op.BoxEasyOpenRequest.Ciphertext,
			op.BoxEasyOpenRequest.Nonce,
			op.BoxEasyOpenRequest.PublicKey,
			op.BoxEasyOpenRequest.SecretKey)
	case *sodium.Request_BoxKeyPairGenerateRequest:
		log.Printf("BoxKeyPairGenerateRequest %d", op.BoxKeyPairGenerateRequest.Foo)
		wireResponse = generateBoxKeyPair()
	case *sodium.Request_BoxSealOpenRequest:
		log.Printf("BoxSealOpenRequest")
		wireResponse = decryptBoxSeal(
			op.BoxSealOpenRequest.Ciphertext,
			box.NewKeyPair(
				op.BoxSealOpenRequest.Keypair.PublicKey,
				op.BoxSealOpenRequest.Keypair.SecretKey))
	case *sodium.Request_BoxSealRequest:
		log.Printf("BoxSealRequest")
		wireResponse = encryptBoxSeal(op.BoxSealRequest.Plaintext, op.BoxSealRequest.PublicKey)
	case *sodium.Request_SignDetachedRequest:
		log.Printf("SignedDetachedRequest")
		wireResponse = signDetached(op.SignDetachedRequest.Message, op.SignDetachedRequest.SecretKey)
	case *sodium.Request_SignDetachedVerifyRequest:
		log.Printf("SignDetachedVerifyRequest")
		wireResponse = signDetachedVerify(
			op.SignDetachedVerifyRequest.Message,
			op.SignDetachedVerifyRequest.PublicKey,
			op.SignDetachedVerifyRequest.Signature)
	case *sodium.Request_SignKeyPairGenerateRequest:
		log.Printf("SignKeyPairGenerateRequest")
		wireResponse = generateSignKeyPair()
	default:
		wireResponse = buildSodiumResponseError(sodium.Error_ERROR_UNKNOWN)
	}

	return wireResponse
}

func signDetached(m []byte, author sign.SecretKey) *sodium.Response {
	digest, err := sign.Detached(m, author)

	if err != nil {
		return buildSodiumResponseError(sodium.Error_ERROR_OPERATION_FAILED)
	}

	response := &sodium.SignDetachedResponse{
		Digest: digest,
	}

	return &sodium.Response{
		SodiumResult: &sodium.Response_SignDetachedResponse{ SignDetachedResponse: response },
	}
}

func signDetachedVerify(m []byte, author sign.PublicKey, sig sign.Digest) *sodium.Response {
	isMatch, err := sign.Verify(m, sig, author)

	if err != nil {
		return buildSodiumResponseError(sodium.Error_ERROR_OPERATION_FAILED)
	}

	response := &sodium.SignDetatchedVerifyResponse{
		SignatureMatches: isMatch,
	}

	return &sodium.Response{
		SodiumResult: &sodium.Response_SignDetachedVerifyResponse{ SignDetachedVerifyResponse: response },
	}
}

func encryptBoxSeal(m []byte, receiver box.PublicKey) *sodium.Response {
	ciphertext, err := box.Seal(m, receiver)

	if err != nil {
		return buildSodiumResponseError(sodium.Error_ERROR_OPERATION_FAILED)
	}

	response := &sodium.BoxSealResponse{
		Ciphertext: ciphertext,
	}

	return &sodium.Response{
		SodiumResult: &sodium.Response_BoxSealResponse{ BoxSealResponse: response },
	}
}

func decryptBoxSeal(c box.Ciphertext, keyPair box.KeyPair) *sodium.Response {
	plaintext, err := box.SealOpen(c, keyPair)

	if err != nil {
		return buildSodiumResponseError(sodium.Error_ERROR_OPERATION_FAILED)
	}

	response := &sodium.BoxSealOpenResponse{
		Plaintext: plaintext,
	}

	return &sodium.Response{
		SodiumResult: &sodium.Response_BoxSealOpenResponse{ BoxSealOpenResponse: response },
	}
}

func decryptBoxEasy(cipherText box.Ciphertext, nonce box.Nonce, sender box.PublicKey, receiver box.SecretKey) *sodium.Response {
	container := box.NewEasyResult(cipherText, nonce)

	plainText, err := box.EasyOpen(container, sender, receiver)

	if err != nil {
		return buildSodiumResponseError(sodium.Error_ERROR_OPERATION_FAILED)
	}

	response := &sodium.BoxEasyOpenResponse{
		Plaintext: plainText,
	}

	return &sodium.Response{
		SodiumResult: &sodium.Response_BoxEasyOpenRespose{ BoxEasyOpenRespose: response },
	}
}

func buildSodiumResponseError(err sodium.Error) *sodium.Response {
	return &sodium.Response{
		SodiumResult: &sodium.Response_Error{ Error: err },
	}
}

func encryptBoxEasy(plaintext []byte, sender box.SecretKey, receiver box.PublicKey) *sodium.Response {
	easyResult, err := box.Easy(plaintext, sender, receiver)

	if err != nil {
		return buildSodiumResponseError(sodium.Error_ERROR_OPERATION_FAILED)
	}

	response := &sodium.BoxEasyResponse{
		Ciphertext: easyResult.Ciphertext,
		Nonce: easyResult.Nonce,
	}

	return &sodium.Response{
		SodiumResult: &sodium.Response_BoxEasyResponse{ BoxEasyResponse: response },
	}
}

func generateSignKeyPair() *sodium.Response {
	keyPair, err := sign.GenerateKeyPair()

	if err != nil {
		return buildSodiumResponseError(sodium.Error_ERROR_OPERATION_FAILED)
	}

	response := &sodium.SignKeyPairGenerateResponse{
		KeyPair: &sodium.KeyPair{
			PublicKey: keyPair.PublicKey,
			SecretKey: keyPair.SecretKey,
		},
	}

	return &sodium.Response{
		SodiumResult: &sodium.Response_SignKeyPairGenerateResponse{ SignKeyPairGenerateResponse: response },
	}
}

