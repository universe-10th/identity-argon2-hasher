package tests

import (
	argon2 "github.com/universe-10th/identity-bcrypt-hasher"
	"testing"
)

func TestHasherPassword(t *testing.T) {
	const pass1 = "foo$123"
	const pass2 = "foo$456"

	if hashed1, err := argon2.Default.Hash(pass1); err != nil {
		t.Errorf("No error should be raised on hashing. Error returned: %s\n", err)
	} else if err := argon2.Default.Validate(pass1, hashed1); err != nil {
		t.Errorf("No error should be raised on validating. Error returned: %s\n", err)
	} else if err := argon2.Default.Validate(pass2, hashed1); err != argon2.PasswordMismatch {
		t.Errorf("Error should be raised on invalid password: argon2.ErrMismatchedHashAndPassword. Error returned: %s\n", err)
	}
}
