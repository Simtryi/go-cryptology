package rsa

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"log"
	"testing"
	"time"
)

func TestBasicVerify(t *testing.T) {
	fmt.Println("Test : basic verify ...")

	//	generate RSA key
	priKey, pubKey := GenRSAKey()

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

	fmt.Printf("... Passed   time: %v μs\n", time.Since(t0).Microseconds())
}

func TestFailVerify(t *testing.T) {
	fmt.Println("Test : verify failed if the private key does not match ...")

	//	generate RSA key
	priKey1, _ := GenRSAKey()
	_, pubKey2 := GenRSAKey()

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

	fmt.Printf("... Passed   time: %v μs\n", time.Since(t0).Microseconds())
}

func BenchmarkSign(b *testing.B) {
	//	generate RSA key
	priKey, _ := GenRSAKey()

	message := Encode("hello world")
	wanted := Sign(message, priKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//	digital signature
		signature := Sign(message, priKey)
		if bytes.Compare(wanted, signature) != 0{
			b.Fatalf("sign failed")
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	//	generate RSA key
	priKey, pubKey := GenRSAKey()

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

func BenchmarkRSA(b *testing.B) {
	//	generate RSA key
	priKey, pubKey := GenRSAKey()

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

func Encode(data interface{}) []byte {
	writer := new(bytes.Buffer)
	enc := gob.NewEncoder(writer)
	if err := enc.Encode(data); err != nil {
		log.Fatalf("encode data failed, %v\n", err)
	}
	return Hash(writer.Bytes())
}

//	hash data
func Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}