package argon2id

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
)

func decodeHash(hash []byte) (param *params, b64Pass []byte, salt []byte, err error) {

	defer func() {
		if pErr := recover(); pErr != nil {
			param = nil
			b64Pass = nil
			salt = nil
			err = fmt.Errorf("panic error : %s", pErr)
		}

	}()

	hashData := bytes.Split(hash, []byte{'$'})
	hashLength := len(hashData)

	if (hashLength) != 6 {
		return nil, nil, nil, fmt.Errorf("hash length invalid")
	}

	p := params{}

	for i, parts := range hashData {

		if len(parts) == 0 {
			continue
		}

		for part := range bytes.SplitSeq(parts, []byte{','}) {

			split := bytes.SplitN(part, []byte{'='}, 2)

			if len(split) == 2 {
				var value uint64
				value, err = strconv.ParseUint(string(split[1]), 10, 64)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("failed to convert : %s", err)
				}

				switch string(split[0]) {
				case "v":
					p.Version = int(value)

				case "m":
					p.Memory = uint32(value)

				case "t":
					p.Iteration = uint32(value)

				case "p":
					p.Parallel = uint8(value)

				default:
					return nil, nil, nil, fmt.Errorf("failed to decode")
				}

				continue
			}

			if bytes.EqualFold(part, []byte("argon2id")) {
				p.Argon2id = true
				continue
			}

			// Password en base64
			if i == hashLength-1 {
				b64Pass = parts
				decodePass := make([]byte, base64.RawStdEncoding.DecodedLen(len(parts)))
				_, err := base64.RawStdEncoding.Decode(decodePass, parts)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("failed to decode pass : %s", err)
				}
				p.HashLength = uint32(len(decodePass))
				continue
			}

			// Salt
			if i == hashLength-2 {

				decodedSalt := make([]byte, base64.RawStdEncoding.DecodedLen(len(parts)))
				nbr, err := base64.RawStdEncoding.Decode(decodedSalt, parts)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("failed to decode salt : %s", err)
				}

				p.SaltLength = uint8(nbr)
				salt = decodedSalt
				continue
			}

		}
	}

	if !p.Argon2id || p.Iteration == 0 || p.Memory == 0 ||
		p.Parallel == 0 || p.SaltLength == 0 || p.Version == 0 || p.HashLength == 0 {
		return nil, nil, nil, fmt.Errorf("hash invalid")
	}

	return &p, b64Pass, salt, nil
}
