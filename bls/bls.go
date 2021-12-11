package bls

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
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

/* -------------------- common: begin -------------------- */

//	digital signature
func Sign(data interface{}, priKey *g2pubs.SecretKey) *g2pubs.Signature {
	writer := new(bytes.Buffer)
	enc := gob.NewEncoder(writer)
	if err := enc.Encode(data); err != nil {
		log.Fatalf("[BLS] encode data failed, %v\n", err)
	}
	dataBytes := Hash(writer.Bytes())

	signature := g2pubs.Sign(dataBytes, priKey)
	return signature
}

//	verify signature
func Verify(data interface{}, pubKey *g2pubs.PublicKey, signature *g2pubs.Signature) bool {
	writer := new(bytes.Buffer)
	enc := gob.NewEncoder(writer)
	if err := enc.Encode(data); err != nil {
		log.Fatalf("[RSA] encode data failed, %v\n", err)
	}
	dataBytes := Hash(writer.Bytes())

	return g2pubs.Verify(dataBytes, pubKey, signature)
}

/* -------------------- common: end -------------------- */



/* -------------------- aggregate: begin -------------------- */

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

//	aggregate signature
func AggregateSignature(sigs []*g2pubs.Signature) *g2pubs.Signature {
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
func VerifyAggregate(data interface{}, pubKeys []*g2pubs.PublicKey, signature *g2pubs.Signature) bool {
	writer := new(bytes.Buffer)
	enc := gob.NewEncoder(writer)
	if err := enc.Encode(data); err != nil {
		log.Fatalf("[RSA] encode data failed, %v\n", err)
	}
	dataBytes := Hash(writer.Bytes())

	return signature.VerifyAggregateCommon(pubKeys, dataBytes)
}

//	batch verify aggregate signature
func VerifyAggregateBatch(data []interface{}, pubKeys []*g2pubs.PublicKey, signature *g2pubs.Signature) bool {
	var dataBytes [][]byte
	for i := 0; i < len(data); i++ {
		writer := new(bytes.Buffer)
		enc := gob.NewEncoder(writer)
		if err := enc.Encode(data[i]); err != nil {
			log.Fatalf("[RSA] encode data failed, %v\n", err)
		}
		dataBytes = append(dataBytes, Hash(writer.Bytes()))
	}

	return signature.VerifyAggregate(pubKeys, dataBytes)
}

/* -------------------- aggregate: end -------------------- */

//	hash data
func Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

