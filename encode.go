package argon2id

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand"

	"golang.org/x/crypto/argon2"
)

// encode permet d'obtenir le hash en base64, le salt en base64 et les paramètres utlisés
func encode(password, salt []byte, p *params) (b64Hash []byte, b64Salt []byte, param *params, err error) {

	if len(salt) == 0 {

		var err error
		// Génération automatique d'un salt
		salt, err = genSalt(p.SaltLength)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// Concertir le salt en base64
	b64Salt = make([]byte, base64.RawStdEncoding.EncodedLen(len(salt)))
	base64.RawStdEncoding.Encode(b64Salt, salt)

	// Génération du hash argon2id
	hash := argon2.IDKey(password, salt, p.Iteration, p.Memory, p.Parallel, p.HashLength)
	b64Hash = make([]byte, base64.RawStdEncoding.EncodedLen(len(hash)))
	// Convertir le hash en base64
	base64.RawStdEncoding.Encode(b64Hash, hash)

	return b64Hash, b64Salt, p, nil
}

// genHash met en forme des données composant un hash argon2id en format final exploitable
func genHash(b64Hash, b64Salt []byte, p *params) ([]byte, error) {

	if p == nil || !p.Argon2id {
		return nil, fmt.Errorf("data hash argon2id invalid")
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Iteration, p.Parallel, b64Salt, b64Hash)

	return buf.Bytes(), nil

}

// genSalt génére un salt. Les valeurs autorisées sont définies par les constantes SALT_MIN_LENGTH et SALT_MAX_LENGTH
func genSalt(length uint8) ([]byte, error) {

	if length < SALT_MIN_LENGTH || length > SALT_MAX_LENGTH {
		return nil, fmt.Errorf("salt must be at least %d characters and must be maximum %d characters long", SALT_MIN_LENGTH, SALT_MAX_LENGTH)
	}

	rnd := rand.New(rand.NewSource(rand.Int63()))

	salt := make([]byte, length)

	for i := range salt {
		salt[i] = byte(rnd.Int63())
	}

	return salt, nil
}
