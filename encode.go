package argon2id

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand"

	"golang.org/x/crypto/argon2"
)

func encode(password, salt []byte, p *Params) (b64Hash []byte, b64Salt []byte, param *Params, err error) {

	if len(salt) == 0 {

		var err error
		// Génération automatique d'un salt
		salt, err = genSalt(p.SaltLen)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	b64Salt = make([]byte, base64.RawStdEncoding.EncodedLen(len(salt)))
	base64.RawStdEncoding.Encode(b64Salt, salt)

	hash := argon2.IDKey(password, salt, p.Iteration, p.Memory, p.Parallel, p.HashLen)
	b64Hash = make([]byte, base64.RawStdEncoding.EncodedLen(len(hash)))
	base64.RawStdEncoding.Encode(b64Hash, hash)

	return b64Hash, b64Salt, p, nil
}

func genHash(b64Hash, b64Salt []byte, p *Params) ([]byte, error) {

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Iteration, p.Parallel, b64Salt, b64Hash)

	return buf.Bytes(), nil

}

// Génération d'un salt
// length doit être >= 8 et <= 100
func genSalt(length uint8) ([]byte, error) {

	if length < 8 || length > 100 {
		return nil, fmt.Errorf("salt must be at least 8 characters and must be maximum 100 characters long")
	}

	rnd := rand.New(rand.NewSource(rand.Int63()))

	salt := make([]byte, length)

	for i := range salt {
		salt[i] = byte(rnd.Int63())
	}

	return salt, nil
}
