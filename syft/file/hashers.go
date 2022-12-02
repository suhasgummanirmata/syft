package file

import (
	"crypto"
	"fmt"
)

func Hashers(names ...string) ([]crypto.Hash, error) {
	supportedHashAlgorithms := make(map[string]crypto.Hash)
	for _, h := range []crypto.Hash{
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA256,
	} {
		supportedHashAlgorithms[DigestAlgorithmName(h)] = h
	}

	var hashers []crypto.Hash
	for _, hashStr := range names {
		hashObj, ok := supportedHashAlgorithms[CleanDigestAlgorithmName(hashStr)]
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm: %s", hashStr)
		}
		hashers = append(hashers, hashObj)
	}
	return hashers, nil
}
