package box

/*
#cgo CFLAGS: -I..
#cgo LDFLAGS: -L.. -lsodium
#include <sodium.h>
*/
import "C"
import (
	"unsafe"
	"fmt"
	"github.com/pkg/errors"
)

type PublicKey []byte
type SecretKey []byte
type Ciphertext []byte
type Nonce []byte

var preconditionError error = errors.New("Precondition failed")

type Error struct {
	errorCode int
}
func (e *Error) Error() string {
	return fmt.Sprintf("libsodium_result=%d", e.errorCode)
}

func newError(result C.int) *Error {
	return &Error{int(result)}
}

type KeyPair struct {
	PublicKey PublicKey
	SecretKey SecretKey
}

type easyResult struct {
	Ciphertext Ciphertext
	Nonce Nonce
}

func allocatePublicKey() PublicKey {
	key := make([]byte, C.crypto_box_publickeybytes())
	return key
}

func allocateSecretKey() SecretKey {
	key := make([]byte, C.crypto_box_secretkeybytes())
	return key
}

func uchar(b []byte) *C.uchar {
	return (*C.uchar)(&b[0])
}

func NewKeyPair(pk PublicKey, sk SecretKey) KeyPair {
	return KeyPair{pk, sk}
}

func GenerateKeyPair() (KeyPair, error) {
	pk := allocatePublicKey()
	sk := allocateSecretKey()

	var err error = nil

	result := C.crypto_box_keypair(uchar(pk), uchar(sk))

	if result != 0 {
		err = newError(result)
	}

	return NewKeyPair(pk, sk), err
}

func Seal(msg []byte, key PublicKey) (Ciphertext, error) {
	if len(key) != int(C.crypto_box_publickeybytes()) {
		return nil, preconditionError
	}

	mlen := len(msg)
	c := make([]byte, int(C.crypto_box_sealbytes()) + mlen)
	var err error = nil

	result := C.crypto_box_seal(uchar(c), uchar(msg), C.ulonglong(mlen), uchar(key))

	if result != 0 {
		err = newError(result)
	}

	return c, err
}

func SealOpen(c Ciphertext, pair KeyPair) ([]byte, error) {
	mlen := len(c) - int(C.crypto_box_sealbytes())
	clen := C.ulonglong(len(c))


	if len(pair.PublicKey) != int(C.crypto_box_publickeybytes()) {
		return nil, preconditionError
	} else if len(pair.SecretKey) != int(C.crypto_box_secretkeybytes()) {
		return nil, preconditionError
	}

	m := make([]byte, mlen)
	var err error = nil

	result := C.crypto_box_seal_open(uchar(m), uchar(c), clen, uchar(pair.PublicKey), uchar(pair.SecretKey))

	if result != 0 {
		err = newError(result)
	}

	return m, err
}

func NewEasyResult(c Ciphertext, n Nonce) *easyResult {
	return &easyResult{c, n}
}

func Easy(msg []byte, sender SecretKey, receiver PublicKey) (*easyResult, error) {
	mlen := len(msg)
	clen :=  mlen + int(C.crypto_box_macbytes())

	if len(sender) != int(C.crypto_box_publickeybytes()) {
		return nil, preconditionError
	} else if len(receiver) != int(C.crypto_box_secretkeybytes()) {
		return nil, preconditionError
	}

	nonce := make([]byte, C.crypto_box_noncebytes())
	c := make([]byte, clen)

	C.randombytes_buf(unsafe.Pointer(&nonce[0]), C.crypto_box_noncebytes())
	var err error = nil

	result := C.crypto_box_easy(uchar(c), uchar(msg), C.ulonglong(mlen), uchar(nonce), uchar(receiver), uchar(sender))

	if result != 0 {
		err = newError(result)
	}

	return NewEasyResult(c, nonce), err
}


func EasyOpen(r *easyResult, sender PublicKey, receiver SecretKey) ([]byte, error) {
	mlen := len(r.Ciphertext) - int(C.crypto_box_macbytes())
	clen := len(r.Ciphertext)
	nonce := r.Nonce

	if len(nonce) != int(C.crypto_box_noncebytes()) {
		return nil, preconditionError
	} else if len(sender) != int(C.crypto_box_publickeybytes()) {
		return nil, preconditionError
	} else if len(receiver) != int(C.crypto_box_secretkeybytes()) {
		return nil, preconditionError
	}

	m := make([]byte, mlen)

	var err error

	result := C.crypto_box_open_easy(uchar(m), uchar(r.Ciphertext), C.ulonglong(clen), uchar(nonce), uchar(sender), uchar(receiver))

	if result != 0 {
		err = newError(result)
	}

	return m, err
}