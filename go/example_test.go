package spake2p_test

import (
	"bytes"
	"fmt"

	spake2p "github.com/9Reg/spake2p/go"
)

// A complete exchange between a Prover and a Verifier in one process. In real
// use the messages cross a network, and the PBKDF output comes from a password
// hash such as scrypt or Argon2id, not from a constant.
func Example() {
	context := []byte("my-app pairing v1")
	idProver, idVerifier := []byte("phone"), []byte("nas")

	// Registration (once). pbkdfOut stands in for 80 bytes of
	// PBKDF(spake2p.PBKDFInput(password, idProver, idVerifier)).
	pbkdfOut := bytes.Repeat([]byte{0x42}, spake2p.PBKDFOutputSize)
	w0, w1, err := spake2p.W0W1FromPBKDFOutput(pbkdfOut)
	if err != nil {
		panic(err)
	}
	l, err := spake2p.Register(w1) // the Verifier stores (w0, l), never w1
	if err != nil {
		panic(err)
	}

	// Exchange.
	prover, shareP, err := spake2p.StartProver(context, idProver, idVerifier, w0, w1)
	if err != nil {
		panic(err)
	}
	verifier, shareV, confirmV, err := spake2p.RespondVerifier(context, idProver, idVerifier, w0, l, shareP)
	if err != nil {
		panic(err)
	}
	confirmP, proverKey, err := prover.Finish(shareV, confirmV)
	if err != nil {
		panic(err)
	}
	verifierKey, err := verifier.Finish(confirmP)
	if err != nil {
		panic(err)
	}

	fmt.Println("keys match:", bytes.Equal(proverKey, verifierKey), "length:", len(proverKey))
	// Output: keys match: true length: 32
}
