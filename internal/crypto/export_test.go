package crypto

import "bytes"

// testCipher returns a Cipher whose nonce source is the given fixed bytes.
// ONLY for use in tests — never in production paths.
func testCipher(nonceBytes []byte) *Cipher {
	return &Cipher{rand: bytes.NewReader(nonceBytes)}
}

// errReader is an io.Reader that always returns an error — used to simulate RNG failure.
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// FailingCipher returns a Cipher whose rand reader always fails with the given error.
// ONLY for use in tests.
func FailingCipher(err error) *Cipher {
	return &Cipher{rand: errReader{err: err}}
}

// EncryptForTest encrypts plaintext with dek and a fixed nonce for golden-vector
// tests in the external crypto_test package. It is ONLY for test use and must
// never be called in production. It panics on error because a failure here means
// the test inputs are malformed, not a runtime condition to handle.
func EncryptForTest(dek DEK, nonce, plaintext, aad []byte) []byte {
	ct, err := testCipher(nonce).Encrypt(dek, plaintext, aad)
	if err != nil {
		panic("EncryptForTest: " + err.Error())
	}
	return ct
}
