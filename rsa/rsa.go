package rsa

import (
	"bytes"
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
	"log"
)

//	generate RSA private key and public key
func GenRSAKey() (priKey *rsa.PrivateKey, pubKey *rsa.PublicKey) {
	priKey, err := rsa.GenerateKey(crand.Reader, 1024)
	if err != nil {
		log.Fatalf("[RSA] generate rsa key failed, %v\n", err)
	}
	pubKey = &priKey.PublicKey
	return
}

//	digital signature
func Sign(data interface{}, priKey *rsa.PrivateKey) []byte {
	writer := new(bytes.Buffer)
	enc := gob.NewEncoder(writer)
	if err := enc.Encode(data); err != nil {
		log.Fatalf("[RSA] encode data failed, %v\n", err)
	}
	dataBytes := Hash(writer.Bytes())

	signature, err := rsa.SignPKCS1v15(crand.Reader, priKey, crypto.SHA256, dataBytes)
	if err != nil {
		log.Fatalf("[RSA] sign failed, %v\n", err)
	}

	return signature
}

//	verify signature
func Verify(data interface{}, pubKey *rsa.PublicKey, signature []byte, ) bool {
	writer := new(bytes.Buffer)
	enc := gob.NewEncoder(writer)
	if err := enc.Encode(data); err != nil {
		log.Fatalf("[RSA] encode data failed, %v\n", err)
	}
	dataBytes := Hash(writer.Bytes())

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, dataBytes[:], signature); err != nil {
		return false
	}

	return true
}

//	hash data
func Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}