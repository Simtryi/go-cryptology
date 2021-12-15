package rs

import (
	"github.com/klauspost/reedsolomon"
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

//	encode data
func Encode(enc reedsolomon.Encoder, data []byte) [][]byte {
	shards, err := enc.Split(data)
	if err != nil {
		log.Fatal(err)
	}

	if err = enc.Encode(shards); err != nil {
		log.Fatal(err)
	}
	return shards
}

func Reconstruct(enc reedsolomon.Encoder, shards [][]byte) {
	if err := enc.Reconstruct(shards); err != nil {
		log.Fatal(err)
	}
}