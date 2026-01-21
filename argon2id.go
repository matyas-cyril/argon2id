package argon2id

import (
	"fmt"
)

// password -> mot de passe à vérifier
func Check[T ByteString](hash T, password T) (verif bool, err error) {

	defer func() {
		if pErr := recover(); pErr != nil {
			verif = false
			err = fmt.Errorf("panic error : %s", pErr)
		}
	}()

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

	fmt.Println("VERIF -> ", paramHash, passHash, string(saltHash))
	fmt.Println("PASSWORD", string(passBytes))
	srcHash, _, _, err := encode(passBytes, saltHash, paramHash)
	fmt.Println(srcHash)

	return false, nil
}

// Hasher via un salt auto généré
func Hash[T ByteString](password T, p *params) (data []byte, err error) {

	defer func() {
		if pErr := recover(); pErr != nil {
			data = nil
			err = fmt.Errorf("panic error : %s", pErr)
		}
	}()

	if p == nil {
		p = DefaultParams
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

func HashWithSalt[T ByteString](password T, salt T, p *params) (data []byte, err error) {

	defer func() {
		if pErr := recover(); pErr != nil {
			data = nil
			err = fmt.Errorf("panic error : %s", pErr)
		}
	}()

	if p == nil {
		p = DefaultParams
	}

	saltBytes, err := strToByte(salt)
	if err != nil {
		return nil, err
	}

	// Longueur >= 8 et <= 100
	if len(saltBytes) != 0 && len(saltBytes) < 8 || len(saltBytes) > 100 {
		return nil, fmt.Errorf("salt must be at least 8 characters and must be maximum 100 characters long")
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
