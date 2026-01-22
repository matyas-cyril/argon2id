package argon2id

import (
	"bytes"
	"fmt"
)

// password -> mot de passe à vérifier
func Check[P ByteString, H ByteString](password P, hash H) (verif bool, err error) {

	defer func() {
		if pErr := recover(); pErr != nil {
			verif = false
			err = fmt.Errorf("panic error : %s", pErr)
		}
	}()

	if isByteStringNull(password) {
		return false, fmt.Errorf("password not defined")
	}

	if isByteStringNull(hash) {
		return false, fmt.Errorf("hash not defined")
	}

	passBytes, err := strToByte(password)
	if err != nil {
		return false, err
	}

	hashB64Bytes, err := strToByte(hash)
	if err != nil {
		return false, err
	}

	// Décomposition du hash
	paramHash, passHash, saltHash, err := decodeHash(hashB64Bytes)
	if err != nil {
		return false, err
	}

	// Chiffrement du mot de passe avec le pass hash du hash décomposé
	srcHash, _, _, err := encode(passBytes, saltHash, paramHash)
	if err != nil {
		return false, err
	}

	return bytes.Equal(passHash, srcHash), nil
}

// Hasher via un salt auto généré
func Hash[P ByteString](password P, p *params) (data []byte, err error) {

	defer func() {
		if pErr := recover(); pErr != nil {
			data = nil
			err = fmt.Errorf("panic error : %s", pErr)
		}
	}()

	if isByteStringNull(password) {
		return nil, fmt.Errorf("password not defined")
	}

	if p == nil {
		return nil, fmt.Errorf("params not defined")
	}

	pwdBytes, err := strToByte(password)
	if err != nil {
		return nil, err
	}

	b64Hash, b64Salt, _, err := encode(pwdBytes, nil, p)
	if err != nil {
		return nil, err
	}

	return genHash(b64Hash, b64Salt, p)
}

func HashWithSalt[P ByteString, S ByteString](password P, salt S, p *params) (data []byte, err error) {

	defer func() {
		if pErr := recover(); pErr != nil {
			data = nil
			err = fmt.Errorf("panic error : %s", pErr)
		}
	}()

	if isByteStringNull(password) {
		return nil, fmt.Errorf("password not defined")
	}

	if isByteStringNull(salt) {
		return nil, fmt.Errorf("salt not defined")
	}

	if p == nil {
		return nil, fmt.Errorf("params not defined")
	}

	saltBytes, err := strToByte(salt)
	if err != nil {
		return nil, err
	}

	pwdBytes, err := strToByte(password)
	if err != nil {
		return nil, err
	}

	b64Hash, b64Salt, _, err := encode(pwdBytes, saltBytes, p)
	if err != nil {
		return nil, err
	}

	return genHash(b64Hash, b64Salt, p)
}

func Params(args map[string]uint64) (p *params, err error) {

	defer func() {
		if pErr := recover(); pErr != nil {
			p = nil
			err = fmt.Errorf("panic error : %s", pErr)
		}
	}()

	p = DefaultParams()

	for key, v := range args {

		switch key {

		case "p": // [1-10]
			if v < 1 || v > 10 {
				return nil, fmt.Errorf("key '%s' invalid", key)
			}
			p.Parallel = uint8(v)

		case "m": // [80-100000]
			if v < 80 || v > 100000 {
				return nil, fmt.Errorf("key '%s' invalid", key)
			}
			p.Memory = uint32(v)

		case "t": // [1-20]
			if v < 1 || v > 20 {
				return nil, fmt.Errorf("key '%s' invalid", key)
			}
			p.Iteration = uint32(v)

		case "saltLength": // [SALT_MIN_LENGTH - SALT_MAX_LENGTH]
			if v < SALT_MIN_LENGTH || v > SALT_MAX_LENGTH {
				return nil, fmt.Errorf("key '%s' invalid", key)
			}
			p.SaltLength = uint8(v)

		case "hashLength": // [4-100]
			if v < 4 || v > 100 {
				return nil, fmt.Errorf("key '%s' invalid", key)
			}
			p.HashLength = uint32(v)

		default:
			return nil, fmt.Errorf("key '%s' not exist", key)
		}
	}
	return p, nil
}
