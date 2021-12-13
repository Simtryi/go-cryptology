package bls

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"github.com/phoreproject/bls/g2pubs"
	"log"
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	fmt.Println("Test : common verify ...")

	//	generate BLS key
	priKey, pubKey := GenBLSKey()

	t0 := time.Now()

	//	digital signature
	message := Encode("hello world")
	signature := Sign(message, priKey)

	//	verify signature
	result := Verify(message, pubKey, signature)
	wanted := true
	if result != wanted {
		t.Fatalf("got result %v but expected %v\n", result, wanted)
	}

	fmt.Printf("... Passed   time: %v ms\n", time.Since(t0).Milliseconds())
}

func TestFailVerify(t *testing.T) {
	fmt.Println("Test : verify failed if the private key does not match ...")

	//	generate BLS key
	priKey1, _ := GenBLSKey()
	_, pubKey2 := GenBLSKey()

	t0 := time.Now()

	//	digital signature
	message := Encode("hello world")
	signature := Sign(message, priKey1)

	//	verify signature
	result := Verify(message, pubKey2, signature)
	wanted := false
	if result != wanted {
		t.Fatalf("got result %v but expected %v\n", result, wanted)
	}

	fmt.Printf("... Passed   time: %v ms\n", time.Since(t0).Milliseconds())
}

func TestAggregatePubKeys(t *testing.T) {
	fmt.Println("Test : aggregate public keys ...")

	var pubKeys []*g2pubs.PublicKey
	var priKeys []*g2pubs.SecretKey
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		priKeys = append(priKeys, priKey)
		pubKeys = append(pubKeys, pubKey)
	}
	aggregatePubKey := AggregatePubKeys(pubKeys)

	message := Encode("hello world")

	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		signature := Sign(message, priKeys[i])
		sigs = append(sigs, signature)
	}
	aggregateSignature := AggregateSignatures(sigs)

	result := Verify(message, aggregatePubKey, aggregateSignature)
	wanted := true
	if result != wanted {
		t.Fatalf("got result %v but expected %v\n", result, wanted)
	}
}

func TestVerifyAggregateSignature(t *testing.T) {
	fmt.Println("Test : aggregate signature ...")

	message := Encode("hello world")

	var pubKeys []*g2pubs.PublicKey
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		signature := Sign(message, priKey)
		sigs = append(sigs, signature)
	}

	t0 := time.Now()

	aggregateSignature := AggregateSignatures(sigs)

	result := VerifyAggregate(message, pubKeys, aggregateSignature)
	wanted := true
	if result != wanted {
		t.Fatalf("got result %v but expected %v\n", result, wanted)
	}

	fmt.Printf("... Passed   time: %v ms\n", time.Since(t0).Milliseconds())
}

func TestBatchVerifyAggregateSignature(t *testing.T) {
	fmt.Println("Test : batch aggregate signature ...")

	var pubKeys []*g2pubs.PublicKey
	var message []interface{}
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		message = append(message, i)
		signature := Sign(Encode(i), priKey)
		sigs = append(sigs, signature)
	}
	batchmessage := BatchEncode(message)

	t0 := time.Now()

	aggregateSignature := AggregateSignatures(sigs)

	result := BatchVerifyAggregate(batchmessage, pubKeys, aggregateSignature)
	wanted := true
	if result != wanted {
		t.Fatalf("got result %v but expected %v\n", result, wanted)
	}

	fmt.Printf("... Passed   time: %v ms\n", time.Since(t0).Milliseconds())
}

func BenchmarkSign(b *testing.B) {
	//	generate BLS key
	priKey, _ := GenBLSKey()

	message := Encode("hello world")
	wanted := Sign(message, priKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//	digital signature
		signature := Sign(message, priKey)
		if  &wanted == &signature {
			b.Fatalf("sign failed")
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	//	generate BLS key
	priKey, pubKey := GenBLSKey()

	//	digital signature
	message := Encode("hello world")
	signature := Sign(message, priKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//	verify signature
		result := Verify(message, pubKey, signature)
		if result != true {
			b.Fatalf("verify failed")
		}
	}
}

func BenchmarkCommonBLS(b *testing.B) {
	//	generate BLS key
	priKey, pubKey := GenBLSKey()

	message := Encode("hello world")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//	digital signature
		signature := Sign(message, priKey)

		//	verify signature
		result := Verify(message, pubKey, signature)
		if result != true {
			b.Fatalf("verify failed")
		}
	}
}

func BenchmarkAggregateSignature(b *testing.B) {
	message := Encode("hello world")

	var pubKeys []*g2pubs.PublicKey
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		signature := Sign(message, priKey)
		sigs = append(sigs, signature)
	}

	wanted := AggregateSignatures(sigs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//	digital signature
		signature := AggregateSignatures(sigs)
		if  &wanted == &signature {
			b.Fatalf("sign failed")
		}
	}
}

func BenchmarkVerifyAggregate(b *testing.B) {
	message := Encode("hello world")

	var pubKeys []*g2pubs.PublicKey
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		signature := Sign(message, priKey)
		sigs = append(sigs, signature)
	}

	aggregateSignature := AggregateSignatures(sigs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := VerifyAggregate(message, pubKeys, aggregateSignature)
		if result != true {
			b.Fatalf("verify aggregate signature failed\n")
		}
	}
}

func BenchmarkBatchVerifyAggregate(b *testing.B) {
	var pubKeys []*g2pubs.PublicKey
	var message []interface{}
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		message = append(message, i)
		signature := Sign(Encode(i), priKey)
		sigs = append(sigs, signature)
	}
	batchmessage := BatchEncode(message)

	aggregateSignature := AggregateSignatures(sigs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := BatchVerifyAggregate(batchmessage, pubKeys, aggregateSignature)
		if result != true {
			b.Fatalf("batch verify aggregate signature failed\n")
		}
	}
}

func BenchmarkAggregateBLS(b *testing.B) {
	message := Encode("hello world")

	var pubKeys []*g2pubs.PublicKey
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		signature := Sign(message, priKey)
		sigs = append(sigs, signature)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aggregateSignature := AggregateSignatures(sigs)
		result := VerifyAggregate(message, pubKeys, aggregateSignature)
		if result != true {
			b.Fatalf("verify aggregate signature failed\n")
		}
	}
}

func Encode(message interface{}) []byte {
	writer := new(bytes.Buffer)
	enc := gob.NewEncoder(writer)
	if err := enc.Encode(message); err != nil {
		log.Fatalf("encode message failed, %v\n", err)
	}
	return Hash(writer.Bytes())
}

func BatchEncode(message []interface{}) [][]byte {
	var result [][]byte
	for i := 0; i < len(message); i++ {
		writer := new(bytes.Buffer)
		enc := gob.NewEncoder(writer)
		if err := enc.Encode(message[i]); err != nil {
			log.Fatalf("encode message failed, %v\n", err)
		}
		result = append(result, Hash(writer.Bytes()))
	}
	return result
}

//	hash message
func Hash(message []byte) []byte {
	h := sha256.New()
	h.Write(message)
	return h.Sum(nil)
}