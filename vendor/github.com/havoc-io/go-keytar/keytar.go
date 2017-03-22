// Package keytar provides an interface for manipulating credentials in a user's
// keychain.
package keytar

import (
	// System imports
	"errors"
	"unicode/utf8"
)

// Error definitions
var (
	ErrUnsupported = errors.New("operation unsupported on this platform")
	ErrUnknown  = errors.New("unknown keychain failure")
	ErrNotFound = errors.New("keychain entry not found")
	ErrInvalidValue = errors.New("an invalid value was provided")
)

// isValidNonNullUTF8 validates a string as UTF-8 with no null bytes.
func isValidNonNullUTF8(s string) bool {
	// Check that this is valid UTF-8
	if !utf8.ValidString(s) {
		return false
	}

	// Check that there are no null-bytes (which are allowed by UTF-8)
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return false
		}
	}

	// All done
	return true
}

// Keychain is the primary interface through which programs interact with the
// system keychain.  All strings passed to this interface must be encoded in
// UTF-8.  GetPassword MAY return a value which is not UTF-8 encoded if the
/// original keychain entry as created by another service which stored the
// password in a non-UTF-8 encoding.
type Keychain interface {
	AddPassword(service, account, password string) error
	GetPassword(service, account string) (string, error)
	DeletePassword(service, account string) error
}

// Global keychain instance
var keychain Keychain = nil

// ReplacePassword replaces a password in a keychain by deleting the original,
// if it exists, and inserting the new value.  It is merely a convenience
// function, built on the Keychain interface.
// NOTE: It'd be nice if this common implementation could be baked into the
// Keychain interface, but such is Go.  We can't even add this to a common
// embedded base, because it requires access to the other Keychain methods.
func ReplacePassword(k Keychain, service, account, newPassword string) error {
	// Delete the password.  We ignore errors, because the password may not
	// exist.  Unfortunately, not every platform returns enough information via
	// its delete call to determine the reason for failure, so we can't check
	// that errors were ErrNotFound, but if there's a more serious problem,
	// AddPassword should pick it up.
	k.DeletePassword(service, account)

	// Add the new password
	return k.AddPassword(service, account, newPassword)
}

// GetKeychain gets the keychain instance for the platform, which might be nil
// if the platform is unsupported (in which case ErrUnsupported will be
// returned).
func GetKeychain() (Keychain, error) {
	// Check if a global keychain has been registered
	if keychain != nil {
		return keychain, nil
	}

	// If not, it's not supported
	return nil, ErrUnsupported
}
