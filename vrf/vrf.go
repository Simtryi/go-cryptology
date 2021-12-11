
package vrf

import (
	"bytes"
	"crypto/rand"
	"github.com/yahoo/coname/ed25519/edwards25519"
	"github.com/yahoo/coname/ed25519/extra25519"
	"golang.org/x/crypto/sha3"
	"io"
	"log"
)

const (
	PublicKeySize    = 32
	PrivateKeySize   = 64
	Size             = 32
	intermediateSize = 32
	ProofSize        = 32 + 32 + intermediateSize
)

//	generate VRF private key and public key
func GenVRFKey() (*[PrivateKeySize]byte, []byte) {
	priKey := new([PrivateKeySize]byte)
	if _, err := io.ReadFull(rand.Reader, priKey[:32]); err != nil {
		log.Fatal(err)
	}

	x, _ := expandSecret(priKey)

	var pubKeyP edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&pubKeyP, x)

	var pubKeyByte [PublicKeySize]byte
	pubKeyP.ToBytes(&pubKeyByte)

	copy(priKey[32:], pubKeyByte[:])
	return priKey, pubKeyByte[:]
}

//	generate random number and its proof
func Prove(message []byte, priKey *[PrivateKeySize]byte) (vrf []byte, proof []byte) {
	// use private key expand vrf secret x
	x, skhr := expandSecret(priKey)

	var cH, rH [64]byte
	var r, c, minusC, t, grB, hrB, iiB [32]byte
	var ii, gr, hr edwards25519.ExtendedGroupElement

	// hash message to curve
	hm := hashToCurve(message)

	edwards25519.GeScalarMult(&ii, x, hm)
	ii.ToBytes(&iiB)

	hash := sha3.NewShake256()
	hash.Write(skhr[:])
	hash.Write(priKey[32:]) // public key, as in ed25519
	hash.Write(message)
	hash.Read(rH[:])
	hash.Reset()
	edwards25519.ScReduce(&r, &rH)

	edwards25519.GeScalarMultBase(&gr, &r)
	edwards25519.GeScalarMult(&hr, &r, hm)
	gr.ToBytes(&grB)
	hr.ToBytes(&hrB)

	hash.Write(grB[:])
	hash.Write(hrB[:])
	hash.Write(message)
	hash.Read(cH[:])
	hash.Reset()
	edwards25519.ScReduce(&c, &cH)

	edwards25519.ScNeg(&minusC, &c)
	edwards25519.ScMulAdd(&t, x, &minusC, &r)

	// make proof
	proof = make([]byte, ProofSize)
	copy(proof[:32], c[:])
	copy(proof[32:64], t[:])
	copy(proof[64:96], iiB[:])

	hash.Write(iiB[:]) // const length: Size
	hash.Write(message)
	vrf = make([]byte, Size)
	hash.Read(vrf[:])
	return
}

//	verify random number and its proof
func Verify(message []byte, pubKeyBytes []byte,  vrfBytes []byte, proof []byte) bool {
	if len(pubKeyBytes) != PublicKeySize || len(vrfBytes) != Size || len(proof) != ProofSize   {
		return false
	}

	var pubKey, vrf, c, t, iiB, cRef, ABytes, BBytes [32]byte
	copy(pubKey[:], pubKeyBytes)
	copy(vrf[:], vrfBytes)

	copy(c[:32], proof[:32])
	copy(t[:32], proof[32:64])
	copy(iiB[:], proof[64:96])

	hash := sha3.NewShake256()
	hash.Write(iiB[:]) // const length
	hash.Write(message)
	var hCheck [Size]byte
	hash.Read(hCheck[:])
	if !bytes.Equal(hCheck[:], vrf[:]) {
		return false
	}
	hash.Reset()

	var P, B, ii, iic edwards25519.ExtendedGroupElement
	var A, hmtP, iicP edwards25519.ProjectiveGroupElement
	if !P.FromBytesBaseGroup(&pubKey) {
		return false
	}
	if !ii.FromBytesBaseGroup(&iiB) {
		return false
	}
	edwards25519.GeDoubleScalarMultVartime(&A, &c, &P, &t)
	A.ToBytes(&ABytes)

	hm := hashToCurve(message)
	edwards25519.GeDoubleScalarMultVartime(&hmtP, &t, hm, &[32]byte{})
	edwards25519.GeDoubleScalarMultVartime(&iicP, &c, &ii, &[32]byte{})
	iicP.ToExtended(&iic)
	hmtP.ToExtended(&B)
	edwards25519.GeAdd(&B, &B, &iic)
	B.ToBytes(&BBytes)

	var cH [64]byte
	hash.Write(ABytes[:]) // const length
	hash.Write(BBytes[:]) // const length
	hash.Write(message)
	hash.Read(cH[:])
	edwards25519.ScReduce(&cRef, &cH)
	return cRef == c
}

//	compute random number
func Compute(message []byte, priKey *[PrivateKeySize]byte) []byte {
	x, _ := expandSecret(priKey)
	var ii edwards25519.ExtendedGroupElement
	var iiB [32]byte
	edwards25519.GeScalarMult(&ii, x, hashToCurve(message))
	ii.ToBytes(&iiB)

	hash := sha3.NewShake256()
	hash.Write(iiB[:]) // const length: Size
	hash.Write(message)
	var vrf [Size]byte
	hash.Read(vrf[:])
	return vrf[:]
}

//	hash message to curve
func hashToCurve(message []byte) *edwards25519.ExtendedGroupElement {
	// H(n) = (f(h(n))^8)
	var hmb [32]byte
	sha3.ShakeSum256(hmb[:], message)
	var hm edwards25519.ExtendedGroupElement
	extra25519.HashToEdwards(&hm, &hmb)
	edwards25519.GeDouble(&hm, &hm)
	edwards25519.GeDouble(&hm, &hm)
	edwards25519.GeDouble(&hm, &hm)
	return &hm
}

//	expand secret
func expandSecret(priKey *[PrivateKeySize]byte) (x, skhr *[32]byte) {
	x, skhr = new([32]byte), new([32]byte)
	hash := sha3.NewShake256()
	hash.Write(priKey[:32])
	hash.Read(x[:])
	hash.Read(skhr[:])
	x[0] &= 248
	x[31] &= 127
	x[31] |= 64
	return
}