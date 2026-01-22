package argon2id_test

import (
	"fmt"
	"testing"

	argon2id "github.com/matyas-cyril/argon2id"
)

var (
	PASSWORD []byte = []byte("Very Strong Password")
	SALT     []byte = []byte("Mettre du sel")
)

// go test -timeout 5s -run ^TestCrypt$
func TestCrypt(t *testing.T) {

	hash, err := argon2id.Hash(PASSWORD, argon2id.DefaultParams())
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Password[%s] -> Argon2id[%s]\n", PASSWORD, hash)
}

// go test -timeout 5s -run ^TestCryptWithSalt$
func TestCryptWithSalt(t *testing.T) {

	hash, err := argon2id.HashWithSalt(PASSWORD, SALT, argon2id.DefaultParams())
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Password[%s] Salt[%s] -> Argon2id[%s]\n", PASSWORD, SALT, hash)
}

// go test -timeout 5s -run ^TestCheck$
func TestCheck(t *testing.T) {

	hash, err := argon2id.Hash(PASSWORD, argon2id.DefaultParams())
	if err != nil {
		t.Fatal(err)
	}

	for _, pass := range []string{"hello", fmt.Sprintf(" %s ", PASSWORD), string(PASSWORD)} {

		check, err := argon2id.Check(pass, hash)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("CHECK : %v\n   Password[%s]\n   Hash[%s]\n\n", check, pass, hash)
	}

}

// go test -timeout 5s -run ^TestParams$
func TestParams(t *testing.T) {

	fmt.Println(argon2id.Params(map[string]uint64{"p": 10, "m": 1000}))
	fmt.Println(argon2id.Params(map[string]uint64{"p": 10, "m": 1000, "t": 100}))
	fmt.Println(argon2id.Params(map[string]uint64{"p": 10, "M": 1000}))
}
