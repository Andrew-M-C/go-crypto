package hash

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HmacSha256 使用 HMACSHA256 方法签名
func HmacSha256(in, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(in)
	return h.Sum(nil)
}
