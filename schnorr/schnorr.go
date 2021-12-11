package schnorr

import (
	"github.com/hbakhtiyor/schnorr"
	"math/big"
)

//	digital signature
func Sign(message [32]byte, priKey *big.Int) ([64]byte, error) {
	return schnorr.Sign(priKey, message)
}

//	verify signature
func Verify(message [32]byte, pubKey [33]byte, signature [64]byte) (bool, error) {
	return schnorr.Verify(pubKey, message, signature)
}

//	batch verify signature
func BatchVerify(message [][32]byte, pubKeys [][33]byte, signatures [][64]byte) (bool, error) {
	return schnorr.BatchVerify(pubKeys, message, signatures)
}

//	aggregate signatures
func AggregateSignatures(message [32]byte, priKeys []*big.Int) ([64]byte, error) {
	return schnorr.AggregateSignatures(priKeys, message)
}