package rsa

import (
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
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
func Sign(message []byte, priKey *rsa.PrivateKey) []byte {
	signature, err := rsa.SignPKCS1v15(crand.Reader, priKey, crypto.SHA256, message)
	if err != nil {
		log.Fatalf("[RSA] sign failed, %v\n", err)
	}

	return signature
}

//	verify signature
func Verify(message []byte, pubKey *rsa.PublicKey, signature []byte, ) bool {
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, message, signature); err != nil {
		return false
	}

	return true
}