package rs

import (
	"fmt"
	"testing"
	"time"
)

func TestEncode(t *testing.T) {
	fmt.Println("Test : encode ...")

	t0 := time.Now()

	data := []byte("hello world")
	enc := MakeEncoder(3, 2)
	Encode(enc, data)

	fmt.Printf("... Passed   time: %v μs\n", time.Since(t0).Microseconds())
}

func TestReconstruct(t *testing.T) {
	fmt.Println("Test : re-construct ...")

	t0 := time.Now()

	data := []byte("hello world")
	enc := MakeEncoder(3, 2)
	shards := Encode(enc, data)
	Reconstruct(enc, shards)

	fmt.Printf("... Passed   time: %v μs\n", time.Since(t0).Microseconds())
}

func BenchmarkEncode(b *testing.B) {
	data := []byte("hello world")
	enc := MakeEncoder(3, 2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(enc, data)
	}
}

func BenchmarkReconstruct(b *testing.B) {
	data := []byte("hello world")
	enc := MakeEncoder(3, 2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shards := Encode(enc, data)
		Reconstruct(enc, shards)
	}
}