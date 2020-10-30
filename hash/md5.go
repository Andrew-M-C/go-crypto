package hash

import (
	"crypto/md5"
)

// MD5 计算 md5 哈希值
func MD5(in []byte) []byte {
	res := md5.Sum(in)
	return res[:]
}
