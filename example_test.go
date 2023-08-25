package nizk_test

import (
	"bytes"
	"fmt"

	"github.com/eliastor/go-nizk"
)

func Example() {

	// Alice
	AliceZK := nizk.NewEd25519Sha3()

	msg := []byte("Arbitrary message which knowledge you want to prove.")
	stamp := []byte("any other information you want to include to the proof: public keys, salts, symmetric keys, etc.")

	AliceProof, AliceFingerprint, err := AliceZK.Proove(msg, stamp)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Alice publishes fingerprint and proof.
	// Bob who knows the same message can generate fingerprint of the message
	//   and can easily verify that Alice also knows the message:

	// Bob
	msg = msg     // Bob knows the message
	stamp = stamp // stamp must be the same, it's offline agreement of the protocol or Alice and Bob

	BobZK := nizk.NewEd25519Sha3()
	BobFingerprint := BobZK.Fingerprint(msg)

	if !bytes.Equal(BobFingerprint, AliceFingerprint) {
		fmt.Println("fingerprints are not equal, so Bob's and Alice's messages are not equal, so nothing to check")
		return
	}

	valid, err := BobZK.Verify(AliceFingerprint, stamp, AliceProof)
	if err != nil {
		fmt.Println(err)
		return
	}
	if !valid {
		fmt.Println("Alice's proof is not valid")
	}
}
