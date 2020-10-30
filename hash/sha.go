package hash

import (
	"crypto/sha256"
)

// Sha256 计算 sha256 哈希值
func Sha256(in []byte) []byte {
	h := sha256.New()
	h.Write(in)
	return h.Sum(nil)
}
