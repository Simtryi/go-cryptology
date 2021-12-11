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
	data := Encode("hello world")
	signature := Sign(data, priKey)

	//	verify signature
	result := Verify(data, pubKey, signature)
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
	data := Encode("hello world")
	signature := Sign(data, priKey1)

	//	verify signature
	result := Verify(data, pubKey2, signature)
	wanted := false
	if result != wanted {
		t.Fatalf("got result %v but expected %v\n", result, wanted)
	}

	fmt.Printf("... Passed   time: %v ms\n", time.Since(t0).Milliseconds())
}

func TestVerifyAggregateSignature(t *testing.T) {
	fmt.Println("Test : aggregate signature ...")

	data := Encode("hello world")

	var pubKeys []*g2pubs.PublicKey
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		signature := Sign(data, priKey)
		sigs = append(sigs, signature)
	}

	t0 := time.Now()

	aggregateSignature := AggregateSignatures(sigs)

	result := VerifyAggregate(data, pubKeys, aggregateSignature)
	wanted := true
	if result != wanted {
		t.Fatalf("got result %v but expected %v\n", result, wanted)
	}

	fmt.Printf("... Passed   time: %v ms\n", time.Since(t0).Milliseconds())
}

func TestBatchVerifyAggregateSignature(t *testing.T) {
	fmt.Println("Test : batch aggregate signature ...")

	var pubKeys []*g2pubs.PublicKey
	var data []interface{}
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		data = append(data, i)
		signature := Sign(Encode(i), priKey)
		sigs = append(sigs, signature)
	}
	batchData := BatchEncode(data)

	t0 := time.Now()

	aggregateSignature := AggregateSignatures(sigs)

	result := BatchVerifyAggregate(batchData, pubKeys, aggregateSignature)
	wanted := true
	if result != wanted {
		t.Fatalf("got result %v but expected %v\n", result, wanted)
	}

	fmt.Printf("... Passed   time: %v ms\n", time.Since(t0).Milliseconds())
}

func BenchmarkSign(b *testing.B) {
	//	generate BLS key
	priKey, _ := GenBLSKey()

	data := Encode("hello world")
	wanted := Sign(data, priKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//	digital signature
		signature := Sign(data, priKey)
		if  &wanted == &signature {
			b.Fatalf("sign failed")
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	//	generate BLS key
	priKey, pubKey := GenBLSKey()

	//	digital signature
	data := Encode("hello world")
	signature := Sign(data, priKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//	verify signature
		result := Verify(data, pubKey, signature)
		if result != true {
			b.Fatalf("verify failed")
		}
	}
}

func BenchmarkCommonBLS(b *testing.B) {
	//	generate BLS key
	priKey, pubKey := GenBLSKey()

	data := Encode("hello world")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//	digital signature
		signature := Sign(data, priKey)

		//	verify signature
		result := Verify(data, pubKey, signature)
		if result != true {
			b.Fatalf("verify failed")
		}
	}
}

func BenchmarkAggregateSignature(b *testing.B) {
	data := Encode("hello world")

	var pubKeys []*g2pubs.PublicKey
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		signature := Sign(data, priKey)
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
	data := Encode("hello world")

	var pubKeys []*g2pubs.PublicKey
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		signature := Sign(data, priKey)
		sigs = append(sigs, signature)
	}

	aggregateSignature := AggregateSignatures(sigs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := VerifyAggregate(data, pubKeys, aggregateSignature)
		if result != true {
			b.Fatalf("verify aggregate signature failed\n")
		}
	}
}

func BenchmarkBatchVerifyAggregate(b *testing.B) {
	var pubKeys []*g2pubs.PublicKey
	var data []interface{}
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		data = append(data, i)
		signature := Sign(Encode(i), priKey)
		sigs = append(sigs, signature)
	}
	batchData := BatchEncode(data)

	aggregateSignature := AggregateSignatures(sigs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := BatchVerifyAggregate(batchData, pubKeys, aggregateSignature)
		if result != true {
			b.Fatalf("batch verify aggregate signature failed\n")
		}
	}
}

func BenchmarkAggregateBLS(b *testing.B) {
	data := Encode("hello world")

	var pubKeys []*g2pubs.PublicKey
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		signature := Sign(data, priKey)
		sigs = append(sigs, signature)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aggregateSignature := AggregateSignatures(sigs)
		result := VerifyAggregate(data, pubKeys, aggregateSignature)
		if result != true {
			b.Fatalf("verify aggregate signature failed\n")
		}
	}
}

func Encode(data interface{}) []byte {
	writer := new(bytes.Buffer)
	enc := gob.NewEncoder(writer)
	if err := enc.Encode(data); err != nil {
		log.Fatalf("encode data failed, %v\n", err)
	}
	return Hash(writer.Bytes())
}

func BatchEncode(data []interface{}) [][]byte {
	var result [][]byte
	for i := 0; i < len(data); i++ {
		writer := new(bytes.Buffer)
		enc := gob.NewEncoder(writer)
		if err := enc.Encode(data[i]); err != nil {
			log.Fatalf("encode data failed, %v\n", err)
		}
		result = append(result, Hash(writer.Bytes()))
	}
	return result
}

//	hash data
func Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}