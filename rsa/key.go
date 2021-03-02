package rsa

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"golang.org/x/crypto/pkcs12"
)

// ParsePrivateKeyPemByFile 从文件中解析 PEM 格式的私钥文件
func ParsePrivateKeyPemByFile(filepath string) (key *rsa.PrivateKey, err error) {
	text, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("ReadFile %s error: %w", filepath, err)
	}

	return ParsePrivateKeyPem(text)
}

// ParsePrivateKeyPem 解析 PEM 私钥正文
func ParsePrivateKeyPem(text []byte) (key *rsa.PrivateKey, err error) {
	blk, _ := pem.Decode(text)
	if blk == nil || len(blk.Bytes) == 0 {
		return nil, errors.New("no key text found")
	}

	key, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err == nil {
		return key, nil
	}
	if strings.Contains(err.Error(), "ParsePKCS1PrivateKey") {
		err = nil
		// and continue trying
	} else {
		err = fmt.Errorf("ParsePKCS1PrivateKey error: %w", err)
		return
	}

	v, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		err = fmt.Errorf("ParsePKCS8PrivateKey error: %w", err)
		return
	}

	key, ok := v.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("converting private key error")
	}
	return key, nil
}

// ParsePrivateKeyPrxByFile 从文件中解析 PRX 私钥
func ParsePrivateKeyPrxByFile(filepath, password string) (key *rsa.PrivateKey, err error) {
	text, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("ReadFile %s error: %w", filepath, err)
	}

	return ParsePrivateKeyPrx(text, password)
}

// ParsePrivateKeyPrx 解析 PRX 私钥正文
func ParsePrivateKeyPrx(text []byte, password string) (key *rsa.PrivateKey, err error) {
	v, _, err := pkcs12.Decode(text, password)
	if err != nil {
		return nil, fmt.Errorf("pkcs12.Decode error: %w", err)
	}

	key, ok := v.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("converting private key error")
	}
	return key, nil
}

// ParsePublicKeyPubByFile 从文件中解析 .pub 公钥
func ParsePublicKeyPubByFile(filepath string) (key *rsa.PublicKey, err error) {
	text, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("ReadFile %s error: %w", filepath, err)
	}

	return ParsePublicKeyPub(text)
}

// ParsePublicKeyPub 解析 .pub 公钥正文
func ParsePublicKeyPub(text []byte) (key *rsa.PublicKey, err error) {
	parts := bytes.Split(text, []byte{' '})
	if len(parts) < 2 {
		return nil, errors.New("invalid public key format, must contain at least tow fields")
	}

	data, err := base64.StdEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("base64.DecodeString error: %w", err)
	}

	info, err := resolvePubData(data)
	if err != nil {
		return
	}

	if f := string(parts[0]); f != info.format {
		return nil, fmt.Errorf("key type invalid: '%s' vs '%s'", f, info.format)
	}

	return &rsa.PublicKey{
		N: info.n,
		E: int(info.e.Int64()),
	}, nil
}

type pubInfo struct {
	format string
	e      *big.Int
	n      *big.Int
}

func resolvePubData(data []byte) (info pubInfo, err error) {
	// format
	data, length, err := resolvePubDataLen(data)
	if err != nil {
		return
	}
	info.format = string(data[:length])
	data = data[length:]

	// E
	data, length, err = resolvePubDataLen(data)
	if err != nil {
		return
	}
	data, info.e, err = resolveBigInt(data, length)
	if err != nil {
		return
	}

	// N
	data, length, err = resolvePubDataLen(data)
	if err != nil {
		return
	}
	data, info.n, err = resolveBigInt(data, length)
	if err != nil {
		return
	}

	// done
	return
}

func resolvePubDataLen(data []byte) (remains []byte, length int, err error) {
	if len(data) < 4 {
		return nil, 0, fmt.Errorf("invalid data length, expected >=%d, buf got %d", 4, len(data))
	}

	buf := bytes.NewBuffer(data[:4])

	i32 := uint32(0)
	err = binary.Read(buf, binary.BigEndian, &i32)
	if err != nil {
		return nil, 0, fmt.Errorf("binary.Read error: %w", err)
	}

	return data[4:], int(i32), nil
}

func resolveBigInt(data []byte, length int) (remains []byte, i *big.Int, err error) {
	if len(data) < length {
		return nil, nil, fmt.Errorf("invalid data length, expected >=%d, buf got %d", length, len(data))
	}
	i = new(big.Int)
	i.SetBytes(data[:length])
	return data[length:], i, nil
}
