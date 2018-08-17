package sign

/*
#cgo LDFLAGS: -L. -lsodium
#include <sodium.h>
*/
import "C"
import (
	"fmt"
	"errors"
)

type PublicKey []byte
type SecretKey []byte
type Digest []byte

var preconditionError error = errors.New("Precondition failed")

type Error struct {
	errorCode int
}
func (e *Error) Error() string {
	return fmt.Sprintf("libsodium_result=%d", e.errorCode)
}

func newError(result C.int) error {
	return &Error{int(result)}
}

type KeyPair struct {
	PublicKey PublicKey
	SecretKey SecretKey
}


func allocatePublicKey() PublicKey {
	key := make([]byte, C.crypto_sign_publickeybytes())
	return key
}

func allocateSecretKey() SecretKey {
	key := make([]byte, C.crypto_sign_secretkeybytes())
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

	result := C.crypto_sign_keypair(uchar(pk), uchar(sk))

	if result != 0 {
		err = newError(result)
	}

	return NewKeyPair(pk, sk), err
}

/*
SODIUM_EXPORT
int crypto_sign_detached(unsigned char *sig, unsigned long long *siglen_p,
                         const unsigned char *m, unsigned long long mlen,
                         const unsigned char *sk);
 */
func Detached(m []byte, sk SecretKey) (Digest, error) {
	if len(sk) != int(C.crypto_sign_secretkeybytes()) {
		return nil, preconditionError
	}

	mlen := len(m)
	var err error = nil
	var zero C.ulonglong

	sig := make([]byte, C.crypto_sign_bytes())
	result := C.crypto_sign_detached(uchar(sig), &zero, uchar(m), C.ulonglong(mlen), uchar(sk))

	if result != 0 {
		err = newError(result)
	}

	return sig, err
}

/*
int crypto_sign_verify_detached(const unsigned char *sig,
                                const unsigned char *m,
                                unsigned long long mlen,
                                const unsigned char *pk)
 */
func Verify(m []byte, d Digest, pk PublicKey) (bool, error) {
	if len(pk) != int(C.crypto_sign_publickeybytes()) {
		return false, preconditionError
	}

	mlen := len(m)

	result := C.crypto_sign_verify_detached(uchar(d), uchar(m), C.ulonglong(mlen), uchar(pk))

	return result == 0, nil
}

