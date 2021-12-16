package merkletree

import (
	"bytes"
	"fmt"
	"testing"
)

func TestProve(t *testing.T) {
	fmt.Println("Test : merkle prove ...")

	data := make([][]byte, 4)
	data[0] = []byte("hello")
	data[1] = []byte("world")
	data[2] = []byte("hi")
	data[3] = []byte("ha")

	tree := MakeTree()
	SetIndex(tree, uint64(0))

	Push(tree, data)

	root, _, _, _ := Prove(tree)
	wanted := Root(tree)

	if bytes.Compare(root, wanted) != 0 {
		t.Fatalf("wanted %v but got %v\n", wanted, root)
	}
}

func TestVerifyProof(t *testing.T) {
	fmt.Println("Test : verify proof ...")

	data := make([][]byte, 4)
	data[0] = []byte("hello")
	data[1] = []byte("world")
	data[2] = []byte("hi")
	data[3] = []byte("ha")

	tree := MakeTree()
	SetIndex(tree, uint64(1))

	Push(tree, data)

	merkleRoot, proofSet, proofIndex, numLeaves := Prove(tree)

	ok := VerifyProof(merkleRoot, proofSet, proofIndex, numLeaves)
	wanted := true
	if ok != true {
		t.Fatalf("wanted %v but got %v\n", wanted, ok)
	}
}
