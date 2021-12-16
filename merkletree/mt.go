package merkletree

import (
	"crypto/sha256"
	"github.com/NebulousLabs/merkletree"
	"log"
)

//	create Merkle tree
func MakeTree()  *merkletree.Tree {
	tree := merkletree.New(sha256.New())
	return tree
}

//	push data
func Push(tree *merkletree.Tree, data [][]byte) {
	for i := 0; i < len(data); i++ {
		tree.Push(data[i])
	}
}

//	get Merkle Tree root
func Root(tree *merkletree.Tree) []byte {
	return tree.Root()
}

//	set index
func SetIndex(tree *merkletree.Tree, i uint64) {
	if err := tree.SetIndex(i); err != nil {
		log.Fatal(err)
	}
}

//	get Merkle Tree prove
func Prove(tree *merkletree.Tree) (merkleRoot []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64) {
	return tree.Prove()
}

//	verify proof
func VerifyProof(merkleRoot []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64) bool {
	return merkletree.VerifyProof(sha256.New(), merkleRoot, proofSet, proofIndex, numLeaves)
}