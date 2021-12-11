package rsa

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestBasicVerify(t *testing.T) {
	fmt.Println("Test : basic verify ...")

	//	generate RSA key
	priKey, pubKey := GenRSAKey()

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

	fmt.Printf("... Passed   time: %v μs\n", time.Since(t0).Microseconds())
}

func TestFailVerify(t *testing.T) {
	fmt.Println("Test : verify failed if the private key does not match ...")

	//	generate RSA key
	priKey1, _ := GenRSAKey()
	_, pubKey2 := GenRSAKey()

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

	fmt.Printf("... Passed   time: %v μs\n", time.Since(t0).Microseconds())
}

func BenchmarkSign(b *testing.B) {
	//	generate RSA key
	priKey, _ := GenRSAKey()

	wanted := Sign("hello world", priKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//	digital signature
		signature := Sign("hello world", priKey)
		if bytes.Compare(wanted, signature) != 0{
			b.Fatalf("sign failed")
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	//	generate RSA key
	priKey, pubKey := GenRSAKey()

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

func BenchmarkRSA(b *testing.B) {
	//	generate RSA key
	priKey, pubKey := GenRSAKey()

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
