package vrf

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestProve(t *testing.T) {
	fmt.Println("Test : vrf prove ...")

	//	generate VRF key
	priKey, _ := GenVRFKey()

	t0 := time.Now()

	//	generate random number and its proof
	message := []byte("hello world")
	vrf, _ := Prove(message, priKey)

	//	compute random number
	wanted := Compute(message, priKey)
	if bytes.Compare(vrf, wanted) != 0 {
		t.Fatalf("got vrf %v but expected %v\n", vrf, wanted)
	}

	fmt.Printf("... Passed   time: %v ms\n", time.Since(t0).Milliseconds())
}


func TestVerify(t *testing.T) {
	fmt.Println("Test : vrf verify ...")

	//	generate VRF key
	priKey, pubKey := GenVRFKey()

	t0 := time.Now()

	//	generate random number and its proof
	message := []byte("hello world")
	vrf, proof := Prove(message, priKey)

	//	verify signature
	result := Verify(message, pubKey, vrf, proof)
	wanted := true
	if result != wanted {
		t.Fatalf("got result %v but expected %v\n", result, wanted)
	}

	fmt.Printf("... Passed   time: %v ms\n", time.Since(t0).Milliseconds())
}

func BenchmarkCompute(b *testing.B) {
	priKey, _ := GenVRFKey()

	message := []byte("hello world")

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Compute(message, priKey)
	}
}

func BenchmarkProve(b *testing.B) {
	priKey, _ := GenVRFKey()

	message := []byte("hello world")

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Prove(message, priKey)
	}
}

func BenchmarkVerify(b *testing.B) {
	priKey, pubKey := GenVRFKey()

	message := []byte("hello world")

	vrf := Compute(message, priKey)
	_, proof := Prove(message, priKey)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Verify(message, pubKey, vrf, proof)
	}
}
