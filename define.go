package argon2id

import (
	"fmt"
	"runtime"

	"golang.org/x/crypto/argon2"
)

const (

	// Longueur en octet du Salt
	SALT_MIN_LENGTH = 16
	SALT_MAX_LENGTH = 64
	SALT_DEF_LENGTH = 16

	// Longueur en octet du hash
	HASH_MIN_LENGTH = 16
	HASH_MAX_LENGTH = 128
	HASH_DEF_LENGTH = 32

	// Memoire m= en Mo
	MEM_MIN_VALUE = 1
	MEM_MAX_VALUE = 4096
	MEM_DEF_VALUE = 32

	// Parallele p=
	THREAD_MIN_VALUE = 1
	THREAD_MAX_VALUE = 20
	THREAD_DEF_VALUE = 4

	// Iterations t=
	TIME_MIN_VALUE = 1
	TIME_MAX_VALUE = 20
	TIME_DEF_VALUE = 3
)

type params struct {
	Memory     uint32 // m=
	Iteration  uint32 // t= time
	Parallel   uint8  // p= thread
	SaltLength uint8  // Longueur du salt si auto-generation
	HashLength uint32
	Version    int
	Argon2id   bool // type
}

type Argon2id struct {
	params *params
	salt   []byte
	hash   []byte
}

type ByteString interface {
	[]byte | string
}

var DefaultParams = func() *params {

	var p uint8 = THREAD_DEF_VALUE
	var t uint32 = TIME_DEF_VALUE
	var m uint32 = MEM_DEF_VALUE * 1024 // 32Mo -> Ko

	if runtime.NumCPU() < 4 {
		p = 1
	}

	return &params{
		Memory:     m,
		Iteration:  t,
		Parallel:   p,
		SaltLength: SALT_DEF_LENGTH,
		HashLength: HASH_DEF_LENGTH,
		Version:    argon2.Version,
		Argon2id:   true,
	}
}

func strToByte[T ByteString](input T) (data []byte, err error) {

	switch p := any(input).(type) {
	case string:
		return []byte(p), nil
	case []byte:
		return []byte(p), nil
	default:
		return nil, fmt.Errorf("unsupported type")
	}

}

func isByteStringNull[T ByteString](input T) bool {

	switch any(input).(type) {
	case []byte:
		return []byte(input) == nil
	}
	return false
}
