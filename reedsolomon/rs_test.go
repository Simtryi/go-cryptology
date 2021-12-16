package rs

import (
	"fmt"
	"log"
	"strconv"
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

func TestReconstruct2(t *testing.T) {
	fmt.Println("Test : re-construct ...")

	//	[[49 48] [49 49] [49 50] [49 51] [49 52] [49 53] [49 54] [49 55] [49 56] [49 57] [50 48] [50 49] [50 50]]
	data := make([][]byte, 10 + 3)
	for i := 0; i < len(data); i++ {
		data[i] = []byte(strconv.Itoa(i + 10))
	}

	enc := MakeEncoder(10, 3)
	//	[[49 48] [49 49] [49 50] [49 51] [49 52] [49 53] [49 54] [49 55] [49 56] [49 57] [49 58] [49 59] [49 60]]
	Encode(enc, data)

	//	[[49 48] [49 49] [49 50] [49 51] [49 52] [49 53] [49 54] [49 55] [49 56] [49 57] [49 58] [49 59] [49 60]]
	shards := make([][]byte, 10 + 3)
	for i := 0; i < len(data); i++ {
		shards[i] = data[i]
	}

	//	[[49 48] [] [] [49 51] [49 52] [49 53] [49 54] [49 55] [49 56] [49 57] [49 58] [49 59] [49 60]]
	shards[1] = nil
	shards[2] = nil

	t0 := time.Now()

	//	[[49 48] [49 49] [49 50] [49 51] [49 52] [49 53] [49 54] [49 55] [49 56] [49 57] [49 58] [49 59] [49 60]]
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