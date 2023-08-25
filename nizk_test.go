package nizk_test

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/eliastor/go-nizk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeMsgStamp() (msg, stamp []byte) {
	msg = make([]byte, 4096)
	io.ReadFull(rand.Reader, msg)
	stamp = make([]byte, 1024)
	io.ReadFull(rand.Reader, stamp)
	return msg, stamp
}

func makeProove(t *testing.T, msg, stamp []byte, zk nizk.Nizk) ([]byte, []byte) {
	var err error
	fingerprint1 := zk.Fingerprint(msg)
	proof, fingerprint2, err := zk.Proove(msg, stamp)
	require.NoError(t, err)
	assert.Equal(t, fingerprint1, fingerprint2)
	return proof, fingerprint2
}

func testSuccessFlow(t *testing.T, id, stamp, proof []byte, zk nizk.Nizk) {
	t.Run("SuccessFlow", func(t *testing.T) {
		valid, err := zk.Verify(id, stamp, proof)
		require.NoError(t, err)
		assert.True(t, valid)
	})
}

func testFailFlow(t *testing.T, id, stamp []byte, proof []byte, zk nizk.Nizk) {
	t.Run("FailFlow", func(t *testing.T) {
		proof[0] ^= 0xFF
		valid, _ := zk.Verify(id, stamp, proof)
		// require.NoError(t, err) there can be the error with invalid point encoding
		assert.False(t, valid)
	})
}

func testFlows(t *testing.T, zk nizk.Nizk) {
	msg, stamp := makeMsgStamp()
	proof, id := makeProove(t, msg, stamp, zk)
	testSuccessFlow(t, id, stamp, proof, zk)
	testFailFlow(t, id, stamp, proof, zk)
}

func TestAllSuites(t *testing.T) {
	suites := []struct {
		Name    string
		Creator func() nizk.Nizk
	}{
		{"ed25519_sha3", nizk.NewEd25519Sha3},
		{"ed25519_sha256", nizk.NewEd25519Sha256},
	}

	for _, suite := range suites {
		name := suite.Name
		zk := suite.Creator()
		t.Run(name, func(t *testing.T) {
			testFlows(t, zk)
		})
	}
}

func benchmarkSuite(b *testing.B, zk nizk.Nizk) {
	msg, stamp := makeMsgStamp()
	id := zk.Fingerprint(msg)
	var proof nizk.Proof
	var err error
	b.Run("Proove", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			proof, _, err = zk.Proove(msg, stamp)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			valid, err := zk.Verify(id, stamp, proof)
			if err != nil {
				b.Fatal(err)
			}
			if !valid {
				b.Fatal("failed verification")
			}
		}
	})
}

func BenchmarkAllSuites(b *testing.B) {
	suites := []struct {
		Name    string
		Creator func() nizk.Nizk
	}{
		{"ed25519_sha3", nizk.NewEd25519Sha3},
		{"ed25519_sha256", nizk.NewEd25519Sha256},
	}
	for _, suite := range suites {
		name := suite.Name
		zk := suite.Creator()
		b.Run(name, func(b *testing.B) {
			benchmarkSuite(b, zk)
		})
	}
}
