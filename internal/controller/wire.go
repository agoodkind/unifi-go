package controller

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/jamesbraid/unifi-emu/inform"
)

const (
	controllerHeaderLength  = 40
	controllerFlagEncrypted = 1
	controllerFlagGCM       = 8
)

func encodeControllerReply(mac [6]byte, payload []byte, keyHex string, useGCM bool) ([]byte, error) {
	key, err := inform.ParseKey(keyHex)
	if err != nil {
		return nil, fault("parse response key", err)
	}
	initializationVector := make([]byte, aes.BlockSize)
	if _, err := rand.Read(initializationVector); err != nil {
		return nil, fault("generate response initialization vector", err)
	}
	flags := uint16(controllerFlagEncrypted)
	bodyLength := len(payload)
	if useGCM {
		flags |= controllerFlagGCM
		bodyLength += 16
	} else {
		bodyLength += aes.BlockSize - len(payload)%aes.BlockSize
	}
	if bodyLength > 1<<32-1 {
		return nil, errors.New("response body exceeds TNBU length")
	}
	header := make([]byte, controllerHeaderLength)
	copy(header[0:4], "TNBU")
	binary.BigEndian.PutUint32(header[4:8], 0)
	copy(header[8:14], mac[:])
	binary.BigEndian.PutUint16(header[14:16], flags)
	copy(header[16:32], initializationVector)
	binary.BigEndian.PutUint32(header[32:36], 1)
	binary.BigEndian.PutUint32(header[36:40], uint32(bodyLength))
	body, err := encryptControllerBody(key, initializationVector, header, payload, useGCM)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, controllerHeaderLength+len(body))
	copy(packet, header)
	copy(packet[controllerHeaderLength:], body)
	return packet, nil
}

func encryptControllerBody(key, initializationVector, header, payload []byte, useGCM bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fault("create response cipher", err)
	}
	if useGCM {
		gcm, err := cipher.NewGCMWithNonceSize(block, aes.BlockSize)
		if err != nil {
			return nil, fault("create response GCM", err)
		}
		return gcm.Seal(nil, initializationVector, payload, header), nil
	}
	paddingLength := aes.BlockSize - len(payload)%aes.BlockSize
	padded := make([]byte, len(payload)+paddingLength)
	copy(padded, payload)
	for index := len(payload); index < len(padded); index++ {
		padded[index] = byte(paddingLength)
	}
	if len(padded)%aes.BlockSize != 0 {
		return nil, errors.New("response plaintext is not block aligned")
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, initializationVector).CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}
