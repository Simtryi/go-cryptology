package ed25519

import (
	"crypto/sha512"
	"crypto/subtle"
	"io"
	"log"

	"github.com/yahoo/coname/ed25519/edwards25519"
)

//	generate private key and public key using randomness from rand
func GenerateKey(rand io.Reader) (priKey *[64]byte, pubKey *[32]byte) {
	priKey = new([64]byte)
	pubKey = new([32]byte)

	_, err := io.ReadFull(rand, priKey[:32])
	if err != nil {
		log.Fatal(err)
	}

	digest := Hash(priKey[:32])

	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var A edwards25519.ExtendedGroupElement
	var hBytes [32]byte
	copy(hBytes[:], digest)
	edwards25519.GeScalarMultBase(&A, &hBytes)
	A.ToBytes(pubKey)

	copy(priKey[32:], pubKey[:])
	return
}

//	digital signature
func Sign(message []byte, priKey *[64]byte) *[64]byte {
	h := sha512.New()
	h.Write(priKey[:32])

	var digest1, messageDigest, hramDigest [64]byte
	var expandedSecretKey [32]byte
	h.Sum(digest1[:0])
	copy(expandedSecretKey[:], digest1[:])
	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 63
	expandedSecretKey[31] |= 64

	h.Reset()
	h.Write(digest1[32:])
	h.Write(message)
	h.Sum(messageDigest[:0])

	var messageDigestReduced [32]byte
	edwards25519.ScReduce(&messageDigestReduced, &messageDigest)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &messageDigestReduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	h.Reset()
	h.Write(encodedR[:])
	h.Write(priKey[32:])
	h.Write(message)
	h.Sum(hramDigest[:0])
	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	var s [32]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &expandedSecretKey, &messageDigestReduced)

	signature := new([64]byte)
	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])
	return signature
}

//	verify signature
func Verify(message []byte, pubKey *[32]byte, signature *[64]byte) bool {
	if signature[63] & 224 != 0 {
		return false
	}

	var A edwards25519.ExtendedGroupElement
	if !A.FromBytes(pubKey) {
		return false
	}
	edwards25519.FeNeg(&A.X, &A.X)
	edwards25519.FeNeg(&A.T, &A.T)

	h := sha512.New()
	h.Write(signature[:32])
	h.Write(pubKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	edwards25519.ScReduce(&hReduced, &digest)

	var R edwards25519.ProjectiveGroupElement
	var b [32]byte
	copy(b[:], signature[32:])
	edwards25519.GeDoubleScalarMultVartime(&R, &hReduced, &A, &b)

	var checkR [32]byte
	R.ToBytes(&checkR)
	return subtle.ConstantTimeCompare(signature[:32], checkR[:]) == 1
}

//	hash data
func Hash(data []byte) []byte {
	h := sha512.New()
	h.Write(data)
	return h.Sum(nil)
}