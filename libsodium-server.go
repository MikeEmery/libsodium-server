package main

import "C"
import (
	"os"
	logger "log"
	"encoding/binary"
	"libsodium-server/sodium"
	"github.com/golang/protobuf/proto"
	"libsodium-server/box"
	"io"
	"libsodium-server/sign"
	"github.com/pkg/errors"
	"time"
)

var log *logger.Logger

const (
	HEADER_SIZE = 4
	MAX_BODY_SIZE = 1024 * 1024 * 10
	BUFFER_SIZE = HEADER_SIZE + MAX_BODY_SIZE
)

var invalidRequestError error

func init() {
	log = logger.New(os.Stderr, "libsodium: ", 0)
	invalidRequestError = errors.New("Failed to parse request")
}

func generateBoxKeyPair() *sodium.Response {
	keyPair, err := box.GenerateKeyPair()

	if err != nil {
		return buildSodiumResponseError(err, sodium.Error_ERROR_OPERATION_FAILED)
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

func accumulate(reader io.Reader, buf []byte, size int, read int) (int, error) {
	for read < size {
		chunk := buf[read:size]
		count, err := reader.Read(chunk)

		if err != nil {
			return 0, err
		}

		read += count
	}

	return read, nil
}

func readIncomingRequest(reader io.Reader, header []byte, bodyBuf []byte) (*sodium.Request, error) {
	count, err := reader.Read(header)

	if err != nil {
		return nil, err
	} else if count == 0 {
		return nil, io.EOF
	}

	size := int(binary.BigEndian.Uint32(header))
	log.Printf("Request size=%v", size)

	if size > MAX_BODY_SIZE {
		return nil, invalidRequestError
	}

	reqBody := bodyBuf[:size]
	count, err = accumulate(reader, reqBody, size, 0)

	log.Printf("Bytes read=%v", count)

	if err != nil {
		return nil, err
	} else if count == 0 {
		return nil, io.EOF
	}

	var request = &sodium.Request{}
	err = proto.Unmarshal(reqBody, request)

	return request, err
}

func main() {
	readFromStdIn()
}

func readFromStdIn() {
	reader := os.Stdin
	writer := os.Stdout

	buf := make([]byte, BUFFER_SIZE)
	headerBuf := buf[:HEADER_SIZE]
	bodyBuf := buf[HEADER_SIZE:BUFFER_SIZE]

	var wireResponse *sodium.Response

	for {
		request, err := readIncomingRequest(reader, headerBuf, bodyBuf)

		if err == io.EOF {
			log.Printf("End of stream")
			break
		} else if err != nil {
			log.Printf("Error %v", err)
			wireResponse = buildSodiumResponseError(err, sodium.Error_ERROR_READ_REQUEST_FAILED)
		} else {
			t1 := time.Now()
			wireResponse = handleRequest(request)
			t2 := time.Now()
			log.Printf("operation time=%f.1 ms", t2.Sub(t1).Seconds()*1000)
		}

		err = writeResponse(writer, wireResponse)

		if err != nil {
			log.Printf("Failed to write response %v", err)
		}
	}
}

func writeResponse(writer io.Writer, response *sodium.Response) error {
	buf, err := proto.Marshal(response)

	if err != nil {
		return err
	}

	outHeader := make([]byte, 4)
	binary.BigEndian.PutUint32(outHeader, uint32(len(buf)))

	_, err = writer.Write(outHeader)

	if err != nil {
		return err
	}

	_, err = writer.Write(buf)

	if err != nil {
		return err
	}

	return nil
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
		log.Printf("BoxKeyPairGenerateRequest")
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
		wireResponse = buildSodiumResponseError(errors.New("unknown request type"), sodium.Error_ERROR_UNKNOWN)
	}

	return wireResponse
}

func signDetached(m []byte, author sign.SecretKey) *sodium.Response {
	digest, err := sign.Detached(m, author)

	if err != nil {
		return buildSodiumResponseError(err, sodium.Error_ERROR_OPERATION_FAILED)
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
		return buildSodiumResponseError(err, sodium.Error_ERROR_OPERATION_FAILED)
	}

	response := &sodium.SignDetachedVerifyResponse{
		SignatureMatches: isMatch,
	}

	return &sodium.Response{
		SodiumResult: &sodium.Response_SignDetachedVerifyResponse{ SignDetachedVerifyResponse: response },
	}
}

func encryptBoxSeal(m []byte, receiver box.PublicKey) *sodium.Response {
	ciphertext, err := box.Seal(m, receiver)

	if err != nil {
		return buildSodiumResponseError(err, sodium.Error_ERROR_OPERATION_FAILED)
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
		return buildSodiumResponseError(err, sodium.Error_ERROR_OPERATION_FAILED)
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
		return buildSodiumResponseError(err, sodium.Error_ERROR_OPERATION_FAILED)
	}

	response := &sodium.BoxEasyOpenResponse{
		Plaintext: plainText,
	}

	return &sodium.Response{
		SodiumResult: &sodium.Response_BoxEasyOpenResponse{ BoxEasyOpenResponse: response },
	}
}

func buildSodiumResponseError(operationError error, err sodium.Error) *sodium.Response {
	log.Printf("error=%v", operationError)
	return &sodium.Response{
		SodiumResult: &sodium.Response_Error{ Error: err },
	}
}

func encryptBoxEasy(plaintext []byte, sender box.SecretKey, receiver box.PublicKey) *sodium.Response {
	easyResult, err := box.Easy(plaintext, sender, receiver)

	if err != nil {
		return buildSodiumResponseError(err, sodium.Error_ERROR_OPERATION_FAILED)
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
		return buildSodiumResponseError(err, sodium.Error_ERROR_OPERATION_FAILED)
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

