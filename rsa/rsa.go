package rsa

import (
	"bytes"
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"log"
)

//	generate RSA public key and private key
func GenRSAKey() (priKeyByte []byte, pubKeyByte []byte) {
	privateKey, err := rsa.GenerateKey(crand.Reader, 1024)
	if err != nil {
		log.Fatalf("[RSA] generate rsa key failed, %v\n", err)
	}

	derPrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derPrivateKey,
	}
	priKeyByte = pem.EncodeToMemory(block)

	publicKey := &privateKey.PublicKey
	derPublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatalf("[RSA] marshal public key failed, %v\n", err)
	}
	block = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derPublicKey,
	}
	pubKeyByte = pem.EncodeToMemory(block)

	return
}

//	get private key
func GetPriKey(priKeyByte []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(priKeyByte)
	if block == nil {
		log.Fatalf("[RSA] decode pri key failed\n")
	}

	priKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("[RSA] parse pri key failed, %v\n", err)
	}

	return priKey
}

//	get public key
func GetPubKey(pubKeyByte []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pubKeyByte)
	if block == nil {
		log.Fatalf("[RSA] decode pub key file failed\n")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("[RSA] parse pub key failed, %v\n", err)
	}

	return pubKey.(*rsa.PublicKey)
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
func Verify(data interface{}, signature []byte, pubKey *rsa.PublicKey) bool {
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