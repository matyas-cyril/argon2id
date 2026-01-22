package argon2id

import (
	"fmt"
	"runtime"

	"golang.org/x/crypto/argon2"
)

const (
	SALT_MIN_LENGTH = 8
	SALT_MAX_LENGTH = 100

	HASH_MIN_LENGTH = 8
	HASH_MAX_LENGTH = 100

	// Memoire m=
	MEM_MIN_VALUE = 1
	MEM_MAX_VALUE = 4096

	// Parallele p=
	THREAD_MIN_VALUE = 1
	THREAD_MAX_VALUE = 10

	// Iterations t=
	TIME_MIN_VALUE = 1
	TIME_MAX_VALUE = 20
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

	var p uint8 = 4
	var t uint32 = 3
	var m uint32 = 64 * 1024 // 64Mo -> Ko

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	if runtime.NumCPU() < 4 {
		p = 1
	}

	return &params{
		Memory:     m,
		Iteration:  t,
		Parallel:   p,
		SaltLength: 16,
		HashLength: 32,
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
