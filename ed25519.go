package nizk

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

const (
	SecretSize = 32
	ProofSize  = 64

	// this prefix is needed to eliminate accidental generation of the same hash outside the proof
	magicPrefix = "Fiat-Shamir NIZK proof made by https://github.com/eliastor?d3eac842bf90905fc958c42422132e984676521f EOL"
)

var (
	_ Nizk = &ed25519Nizk{}
)

type ed25519Nizk struct {
	hashSum func(data []byte) [SecretSize]byte
}

func (n *ed25519Nizk) fingerprintPointScalar(sum []byte) (*edwards25519.Point, *edwards25519.Scalar) {
	sc, _ := edwards25519.NewScalar().SetBytesWithClamping(sum)
	point := edwards25519.NewIdentityPoint().ScalarBaseMult(sc)
	return point, sc
}

func (n *ed25519Nizk) messagePointID(message []byte) (*edwards25519.Point, *edwards25519.Scalar) {
	sum := n.hashSum(append([]byte(magicPrefix), message...))
	s := make([]byte, SecretSize)
	copy(s, sum[:])
	X, x := n.fingerprintPointScalar(s)
	return X, x
}

func (n *ed25519Nizk) Fingerprint(message []byte) (id []byte) {
	point, _ := n.messagePointID(message)
	id = point.Bytes()
	return
}

func (n *ed25519Nizk) calcGYTPHashScalar(fingerprint, pT, stamp []byte) (*edwards25519.Scalar, error) {
	gytp := []byte{}
	gytp = append(gytp, edwards25519.NewGeneratorPoint().Bytes()...)
	gytp = append(gytp, fingerprint...)
	gytp = append(gytp, pT...)
	gytp = append(gytp, stamp...)
	sum := n.hashSum(gytp)
	c, err := edwards25519.NewScalar().SetBytesWithClamping(sum[:])
	if err != nil {
		return nil, fmt.Errorf("can't create c scalar: %w", err)
	}
	return c, nil
}

func (n *ed25519Nizk) Proove(msg []byte, stamp []byte) (Proof, []byte, error) {
	vb := [SecretSize]byte{}
	_, err := io.ReadFull(rand.Reader, vb[:])
	if err != nil {
		return nil, nil, err
	}
	v, err := edwards25519.NewScalar().SetBytesWithClamping(vb[:])
	if err != nil {
		return nil, nil, fmt.Errorf("can't create r scalar: %w", err)
	}

	T := edwards25519.NewIdentityPoint().ScalarBaseMult(v)

	Tb := T.Bytes()

	X, x := n.messagePointID(msg)
	fingerprint := X.Bytes()

	c, err := n.calcGYTPHashScalar(fingerprint, Tb, stamp) // h = hash(G||id||vG||stamp)
	if err != nil {
		return nil, nil, fmt.Errorf("can't calculate GYTP hash: %w", err)
	}

	c.Negate(c)
	r := edwards25519.NewScalar().MultiplyAdd(c, x, v) // (-h) * x + v

	var proof [ProofSize]byte
	copy(proof[:SecretSize], Tb)
	copy(proof[SecretSize:], r.Bytes())

	return proof[:], fingerprint, nil
}

func (n *ed25519Nizk) ProofSize() int {
	return ProofSize
}

func (n *ed25519Nizk) FingerprintSize() int {
	return SecretSize
}

func (n *ed25519Nizk) Verify(id []byte, stamp []byte, proof Proof) (bool, error) {
	if len(proof) != n.ProofSize() {
		return false, fmt.Errorf("wrong size of proof, expected %d", n.ProofSize())
	}

	Tb := proof[:SecretSize]
	rb := proof[SecretSize:]

	r, err := edwards25519.NewScalar().SetCanonicalBytes(rb)
	if err != nil {
		return false, fmt.Errorf("can't read r scalar: %w", err)
	}

	X, err := edwards25519.NewIdentityPoint().SetBytes(id)
	if err != nil {
		return false, fmt.Errorf("can't read X point: %w", err)
	}

	c, err := n.calcGYTPHashScalar(id, Tb, stamp)
	if err != nil {
		return false, fmt.Errorf("can't calculate GYTP hash: %w", err)
	}

	T, err := edwards25519.NewIdentityPoint().SetBytes(Tb)
	if err != nil {
		return false, fmt.Errorf("can't read T point: %w", err)
	}

	calculatedT := edwards25519.NewIdentityPoint().VarTimeDoubleScalarBaseMult(c, X, r)

	return T.Equal(calculatedT) == 1, nil
}

func NewEd25519Sha3() Nizk {
	return &ed25519Nizk{
		hashSum: sha3.Sum256,
	}
}

func NewEd25519Sha256() Nizk {
	return &ed25519Nizk{
		hashSum: sha256.Sum256,
	}
}
