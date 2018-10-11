package sodium

/*
#cgo CFLAGS: -I..
#cgo LDFLAGS: -L.. -lsodium
#include <sodium.h>
*/
import "C"
import (
	"errors"
	"strconv"
)

func Init() error {
	initResult := int64(C.sodium_init())
	if initResult < 0 {
		return errors.New("Sodium failed to initialize, code=" + strconv.FormatInt(initResult, 10))
	}

	return nil
}