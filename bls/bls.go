package bls

import (
	"crypto/rand"
	"github.com/phoreproject/bls/g2pubs"
	"log"
)

//	generate BLS private key and public key
func GenBLSKey() (priKey *g2pubs.SecretKey, pubKey *g2pubs.PublicKey) {
	priKey, err := g2pubs.RandKey(rand.Reader)
	if err != nil {
		log.Fatalf("[BLS] generate secret key failed, %v\n", err)
	}
	pubKey = g2pubs.PrivToPub(priKey)
	return
}

//	digital signature
func Sign(message []byte, priKey *g2pubs.SecretKey) *g2pubs.Signature {
	return g2pubs.Sign(message, priKey)
}

//	verify signature
func Verify(message []byte, pubKey *g2pubs.PublicKey, signature *g2pubs.Signature) bool {
	return g2pubs.Verify(message, pubKey, signature)
}

//	aggregate public keys
func AggregatePubKeys(pubKeys []*g2pubs.PublicKey) *g2pubs.PublicKey {
	if len(pubKeys) == 0 {
		log.Fatalf("[BLS] no public key to aggregate\n")
	}

	aggregatePubKey := g2pubs.NewAggregatePubkey()
	for _, pubKey := range pubKeys {
		aggregatePubKey.Aggregate(pubKey)
	}

	return aggregatePubKey
}

//	aggregate signatures
func AggregateSignatures(sigs []*g2pubs.Signature) *g2pubs.Signature {
	if len(sigs) == 0 {
		log.Fatalf("[BLS] no signature to aggregate\n")
	}

	temp := make([]*g2pubs.Signature, 0, len(sigs))
	for _, sig := range sigs {
		temp = append(temp, sig)
	}

	return g2pubs.AggregateSignatures(temp)
}

//	verify aggregate signature
func VerifyAggregate(message []byte, pubKeys []*g2pubs.PublicKey, signature *g2pubs.Signature) bool {
	return signature.VerifyAggregateCommon(pubKeys, message)
}

//	batch verify aggregate signature
func BatchVerifyAggregate(message [][]byte, pubKeys []*g2pubs.PublicKey, signature *g2pubs.Signature) bool {
	return signature.VerifyAggregate(pubKeys, message)
}
