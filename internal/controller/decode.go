package controller

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"

	"github.com/golang/snappy"
	"github.com/jamesbraid/unifi-emu/inform"
)

const (
	maxInformPayload = 8 * 1024 * 1024
	informHeaderSize = 40
	informEncrypted  = 1
	informZlib       = 2
	informSnappy     = 4
	informGCM        = 8
)

// decodeInform accepts only the encrypted request formats verified by the controller.
func decodeInform(data []byte, keyHex string) (*inform.Packet, error) {
	if len(data) < informHeaderSize || len(data) > maxInformPayload || string(data[:4]) != "TNBU" {
		return nil, errors.New("invalid inform header")
	}
	if binary.BigEndian.Uint32(data[4:8]) > 1 || binary.BigEndian.Uint32(data[32:36]) != 1 {
		return nil, errors.New("unsupported inform version")
	}
	flags := binary.BigEndian.Uint16(data[14:16])
	if flags&informEncrypted == 0 || flags & ^uint16(15) != 0 || flags&(informZlib|informSnappy) == informZlib|informSnappy {
		return nil, errors.New("unsupported inform flags")
	}
	if int64(binary.BigEndian.Uint32(data[36:40])) != int64(len(data)-informHeaderSize) {
		return nil, errors.New("invalid inform payload length")
	}
	plain, err := decryptInform(data, keyHex, flags)
	if err != nil {
		return nil, err
	}
	switch {
	case flags&informSnappy != 0:
		length, err := snappy.DecodedLen(plain)
		if err != nil || length > maxInformPayload {
			return nil, errors.New("invalid or oversized snappy inform")
		}
		plain, err = snappy.Decode(nil, plain)
		if err != nil {
			return nil, errors.New("invalid snappy inform")
		}
	case flags&informZlib != 0:
		reader, err := zlib.NewReader(bytes.NewReader(plain))
		if err != nil {
			return nil, errors.New("invalid zlib inform")
		}
		defer reader.Close()
		plain, err = io.ReadAll(io.LimitReader(reader, maxInformPayload+1))
		if err != nil {
			return nil, errors.New("invalid zlib inform")
		}
	}
	if len(plain) > maxInformPayload {
		return nil, errors.New("oversized decoded inform")
	}
	packet := &inform.Packet{Payload: plain}
	copy(packet.MAC[:], data[8:14])
	return packet, nil
}

func decryptInform(data []byte, keyHex string, flags uint16) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 16 {
		return nil, errors.New("invalid inform key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("invalid inform cipher")
	}
	iv, body := data[16:32], data[informHeaderSize:]
	if flags&informGCM == 0 {
		return decryptInformCBC(block, iv, body)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, errors.New("invalid inform cipher")
	}
	// The complete 40-byte request header is authenticated, including its length.
	plain, err := gcm.Open(nil, iv, body, data[:informHeaderSize])
	if err != nil {
		return nil, errors.New("invalid inform authentication")
	}
	return plain, nil
}

func decryptInformCBC(block cipher.Block, iv, body []byte) ([]byte, error) {
	if len(body) == 0 || len(body)%aes.BlockSize != 0 {
		return nil, errors.New("invalid inform ciphertext length")
	}
	plain := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, body)
	padding := int(plain[len(plain)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(plain) {
		return nil, errors.New("invalid inform padding")
	}
	for _, value := range plain[len(plain)-padding:] {
		if int(value) != padding {
			return nil, errors.New("invalid inform padding")
		}
	}
	return plain[:len(plain)-padding], nil
}
