package ed25519

import (
	"fmt"
	"testing"
	"time"
)

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 0
	}
	return len(buf), nil
}

func TestSignVerify(t *testing.T) {
	fmt.Println("Test : sign verify ...")

	//	generate key
	var zero zeroReader
	priKey, pubKey := GenerateKey(zero)

	t0 := time.Now()

	//	digital signature
	message := []byte("test message")
	signature := Sign(message, priKey)

	//	verify signature
	result := Verify(message, pubKey, signature)
	wanted := true
	if result != wanted {
		t.Fatalf("got result %v but expected %v\n", result, wanted)
	}

	fmt.Printf("... Passed   time: %v ms\n", time.Since(t0).Milliseconds())
}

func BenchmarkSign(b *testing.B) {
	//	generate key
	var zero zeroReader
	priKey, _ := GenerateKey(zero)

	message := []byte("hello world")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//	digital signature
		Sign(message, priKey)
	}
}

func BenchmarkVerify(b *testing.B) {
	//	generate key
	var zero zeroReader
	priKey, pubKey := GenerateKey(zero)

	//	digital signature
	message := []byte("hello world")
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

func BenchmarkEd(b *testing.B) {
	//	generate key
	var zero zeroReader
	priKey, pubKey := GenerateKey(zero)

	message := []byte("hello world")

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