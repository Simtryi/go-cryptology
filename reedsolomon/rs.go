package rs

import (
	"github.com/klauspost/reedsolomon"
	"io"
	"log"
)

//	create reed-solomon encoder
func MakeEncoder(dataShards int, parityShards int) reedsolomon.Encoder {
	enc, err :=  reedsolomon.New(dataShards, parityShards)
	if err != nil {
		log.Fatal(err)
	}
	return enc
}

//	split data
func Split(enc reedsolomon.Encoder, data []byte) [][]byte {
	shards, err := enc.Split(data)
	if err != nil {
		log.Fatal(err)
	}
	return shards
}

//	join data
func Join(enc reedsolomon.Encoder, dst io.Writer, shards [][]byte, outSize int) {
	if err := enc.Join(dst, shards, outSize); err != nil {
		log.Fatal(err)
	}
}

//	encode shards
func Encode(enc reedsolomon.Encoder, shards [][]byte) {
	if err := enc.Encode(shards); err != nil {
		log.Fatal(err)
	}
}

//	verify whether shards need to reconstruct
func Verify(enc reedsolomon.Encoder, shards [][]byte) bool {
	result, _ := enc.Verify(shards)
	return result
}

//	re-construct data
func Reconstruct(enc reedsolomon.Encoder, shards [][]byte) {
	if err := enc.Reconstruct(shards); err != nil {
		log.Fatal(err)
	}
}