package bls

import (
	"fmt"
	"github.com/phoreproject/bls/g2pubs"
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	fmt.Println("Test : common verify ...")

	//	generate BLS key
	priKey, pubKey := GenBLSKey()

	t0 := time.Now()

	//	digital signature
	data := "hello world"
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
	data := "hello world"
	signature := Sign(data, priKey1)

	//	verify signature
	result := Verify(data, pubKey2, signature)
	wanted := false
	if result != wanted {
		t.Fatalf("got result %v but expected %v\n", result, wanted)
	}

	fmt.Printf("... Passed   time: %v ms\n", time.Since(t0).Milliseconds())
}

func TestAggregateSignature(t *testing.T) {
	fmt.Println("Test : aggregate signature ...")

	var pubKeys []*g2pubs.PublicKey
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		signature := Sign("hello world", priKey)
		sigs = append(sigs, signature)
	}

	t0 := time.Now()

	aggregateSignature := AggregateSignature(sigs)

	result := VerifyAggregate("hello world", pubKeys, aggregateSignature)
	wanted := true
	if result != wanted {
		t.Fatalf("got result %v but expected %v\n", result, wanted)
	}

	fmt.Printf("... Passed   time: %v ms\n", time.Since(t0).Milliseconds())
}

func TestAggregateSignatureBatch(t *testing.T) {
	fmt.Println("Test : batch aggregate signature ...")

	var pubKeys []*g2pubs.PublicKey
	var data []interface{}
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		data = append(data, i)
		signature := Sign(i, priKey)
		sigs = append(sigs, signature)
	}

	t0 := time.Now()

	aggregateSignature := AggregateSignature(sigs)

	result := VerifyAggregateBatch(data, pubKeys, aggregateSignature)
	wanted := true
	if result != wanted {
		t.Fatalf("got result %v but expected %v\n", result, wanted)
	}

	fmt.Printf("... Passed   time: %v ms\n", time.Since(t0).Milliseconds())
}

func BenchmarkSign(b *testing.B) {
	//	generate BLS key
	priKey, _ := GenBLSKey()

	wanted := Sign("hello world", priKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//	digital signature
		signature := Sign("hello world", priKey)
		if  &wanted == &signature {
			b.Fatalf("sign failed")
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	//	generate BLS key
	priKey, pubKey := GenBLSKey()

	//	digital signature
	signature := Sign("hello world", priKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//	verify signature
		result := Verify("hello world", pubKey, signature)
		if result != true {
			b.Fatalf("verify failed")
		}
	}
}

func BenchmarkCommonBLS(b *testing.B) {
	//	generate BLS key
	priKey, pubKey := GenBLSKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//	digital signature
		signature := Sign(i, priKey)

		//	verify signature
		result := Verify(i, pubKey, signature)
		if result != true {
			b.Fatalf("verify failed")
		}
	}
}

func BenchmarkAggregateSignature(b *testing.B) {
	var pubKeys []*g2pubs.PublicKey
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		signature := Sign("hello world", priKey)
		sigs = append(sigs, signature)
	}

	wanted := AggregateSignature(sigs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//	digital signature
		signature := AggregateSignature(sigs)
		if  &wanted == &signature {
			b.Fatalf("sign failed")
		}
	}
}

func BenchmarkVerifyAggregate(b *testing.B) {
	var pubKeys []*g2pubs.PublicKey
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		signature := Sign("hello world", priKey)
		sigs = append(sigs, signature)
	}

	aggregateSignature := AggregateSignature(sigs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := VerifyAggregate("hello world", pubKeys, aggregateSignature)
		if result != true {
			b.Fatalf("verify aggregate signature failed\n")
		}
	}
}

func BenchmarkVerifyAggregateBatch(b *testing.B) {
	var pubKeys []*g2pubs.PublicKey
	var data []interface{}
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		data = append(data, i)
		signature := Sign(i, priKey)
		sigs = append(sigs, signature)
	}

	aggregateSignature := AggregateSignature(sigs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := VerifyAggregateBatch(data, pubKeys, aggregateSignature)
		if result != true {
			b.Fatalf("batch verify aggregate signature failed\n")
		}
	}
}

func BenchmarkAggregateBLS(b *testing.B) {
	var pubKeys []*g2pubs.PublicKey
	var sigs []*g2pubs.Signature
	for i := 0; i < 3; i++ {
		priKey, pubKey := GenBLSKey()
		pubKeys = append(pubKeys, pubKey)

		signature := Sign("hello world", priKey)
		sigs = append(sigs, signature)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aggregateSignature := AggregateSignature(sigs)
		result := VerifyAggregate("hello world", pubKeys, aggregateSignature)
		if result != true {
			b.Fatalf("verify aggregate signature failed\n")
		}
	}
}