package rs

import (
	"fmt"
	"log"
	"testing"
	"time"
)

func TestEncode(t *testing.T) {
	fmt.Println("Test : encode ...")

	data := []byte("hello world")
	enc := MakeEncoder(10, 5)

	t0 := time.Now()

	shards := Split(enc, data)
	Encode(enc, shards)

	fmt.Printf("... Passed   time: %v μs\n", time.Since(t0).Microseconds())
}

func TestVerify(t *testing.T) {
	fmt.Println("Test : verify ...")

	data := []byte("hello world")
	enc := MakeEncoder(10, 3)

	shards := Split(enc, data)
	Encode(enc, shards)

	t0 := time.Now()

	ok := Verify(enc, shards)
	wanted := true
	if ok != wanted {
		log.Fatalf("expected %v but got %v\n", wanted, ok)
	}

	shards[1] = nil
	shards[2] = nil
	ok = Verify(enc, shards)
	wanted = false
	if ok != wanted {
		log.Fatalf("expected %v but got %v\n", wanted, ok)
	}

	fmt.Printf("... Passed   time: %v μs\n", time.Since(t0).Microseconds())
}

func TestReconstruct(t *testing.T) {
	fmt.Println("Test : re-construct ...")

	data := []byte("hello world")

	enc := MakeEncoder(10, 3)

	//	[[104 101] [108 108] [111 32] [119 111] [114 108] [100 0] [0 0] [0 0] [0 0] [0 0] [0 0] [0 0] [0 0]]
	shards := Split(enc, data)
	Encode(enc, shards)

	t0 := time.Now()

	shards[1] = nil
	shards[2] = nil
	Reconstruct(enc, shards)

	fmt.Printf("... Passed   time: %v μs\n", time.Since(t0).Microseconds())
}

func BenchmarkEncode(b *testing.B) {
	data := []byte("hello world")
	enc := MakeEncoder(3, 2)

	shards := Split(enc, data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(enc, shards)
	}
}

func BenchmarkReconstruct(b *testing.B) {
	data := []byte("hello world")
	enc := MakeEncoder(3, 2)

	shards := Split(enc, data)
	Encode(enc, shards)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Reconstruct(enc, shards)
	}
}