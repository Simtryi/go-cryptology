package rsa

import (
	"fmt"
	"testing"
	"time"
)

func TestBasicVerify(t *testing.T) {
	fmt.Println("Test : basic verify ...")

	//	generate RSA key
	priKeyByte, pubKeyByte := GenRSAKey()

	//	get private key and public key
	priKey := GetPriKey(priKeyByte)
	pubKey := GetPubKey(pubKeyByte)

	t0 := time.Now()

	//	digital signature
	data := "hello world"
	signature := Sign(data, priKey)

	//	verify signature
	result := Verify(data, signature, pubKey)
	wanted := true
	if result != wanted {
		t.Fatalf("got result %v but expected %v\n", result, wanted)
	}

	fmt.Printf("... Passed   time: %v μs\n", time.Since(t0).Microseconds())
}

func TestFailVerify(t *testing.T) {
	fmt.Println("Test : verify failed if the private key does not match ...")

	//	generate RSA key
	priKeyByte1, _ := GenRSAKey()
	_, pubKeyByte2 := GenRSAKey()

	//	get private key and public key
	priKey1 := GetPriKey(priKeyByte1)
	pubKey2 := GetPubKey(pubKeyByte2)

	t0 := time.Now()

	//	digital signature
	data := "hello world"
	signature := Sign(data, priKey1)

	//	verify signature
	result := Verify(data, signature, pubKey2)
	wanted := false
	if result != wanted {
		t.Fatalf("got result %v but expected %v\n", result, wanted)
	}

	fmt.Printf("... Passed   time: %v μs\n", time.Since(t0).Microseconds())
}

func BenchmarkRSA(b *testing.B) {
	//	generate RSA key
	priKeyByte, pubKeyByte := GenRSAKey()

	//	get private key and public key
	priKey := GetPriKey(priKeyByte)
	pubKey := GetPubKey(pubKeyByte)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//	digital signature
		signature := Sign(i, priKey)

		//	verify signature
		result := Verify(i, signature, pubKey)
		if result != true {
			b.Fatalf("verify failed")
		}
	}
}