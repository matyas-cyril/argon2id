package argon2id

import (
	"fmt"
	"runtime"

	"golang.org/x/crypto/argon2"
)

type params struct {
	Memory     uint32 // m=
	Iteration  uint32 // t=
	Parallel   uint8  // p=
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

	if runtime.NumCPU() < 4 {
		p = 1
	}

	return &params{
		Memory:     4,
		Iteration:  3,
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
