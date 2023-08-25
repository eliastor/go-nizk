package nizk

type Suite interface{}

type Proof []byte

type Nizk interface {
	Proove(msg []byte, stamp []byte) (proof Proof, fingerprint []byte, err error)
	ProofSize() int
	FingerprintSize() int
	Fingerprint(msg []byte) []byte
	Verify(fingerprint []byte, stamp []byte, proof Proof) (valid bool, err error)
}
