package keytar

// #cgo LDFLAGS: -framework CoreFoundation -framework Security
// #include <stdlib.h>
// #include <CoreFoundation/CoreFoundation.h>
// #include <Security/Security.h>
import "C"

import (
	// System imports
	"unsafe"
)

// keychainOSX implements the Keychain interface on OS X by using the Security
// framework to store items in the user's login keychain.
type keychainOSX struct{}

func (*keychainOSX) AddPassword(service, account, password string) error {
	// Validate input
	serviceValid := isValidNonNullUTF8(service)
	accountValid := isValidNonNullUTF8(account)
	passwordValid := isValidNonNullUTF8(password)
	if !(serviceValid && accountValid && passwordValid) {
		return ErrInvalidValue
	}

	// Convert values to C strings
	serviceCStr := C.CString(service)
	defer C.free(unsafe.Pointer(serviceCStr))
	accountCStr := C.CString(account)
	defer C.free(unsafe.Pointer(accountCStr))
	passwordBlob := unsafe.Pointer(C.CString(password))
	defer C.free(passwordBlob)

	// Try to add the password
	status := C.SecKeychainAddGenericPassword(
		nil,
		C.UInt32(len(service)),
		serviceCStr,
		C.UInt32(len(account)),
		accountCStr,
		C.UInt32(len(password)),
		passwordBlob,
		nil,
	)

	// Check for errors
	if status != C.errSecSuccess {
		return ErrUnknown
	}

	// All done
	return nil
}

func (*keychainOSX) GetPassword(service, account string) (string, error) {
	// Validate input
	serviceValid := isValidNonNullUTF8(service)
	accountValid := isValidNonNullUTF8(account)
	if !(serviceValid && accountValid) {
		return "", ErrInvalidValue
	}

	// Convert values to C strings
	serviceCStr := C.CString(service)
	defer C.free(unsafe.Pointer(serviceCStr))
	accountCStr := C.CString(account)
	defer C.free(unsafe.Pointer(accountCStr))

	// Look for a match
	var passwordData unsafe.Pointer
	var passwordDataLength C.UInt32
	status := C.SecKeychainFindGenericPassword(
		nil,
		C.UInt32(len(service)),
		serviceCStr,
		C.UInt32(len(account)),
		accountCStr,
		&passwordDataLength,
		&passwordData,
		nil,
	)

	// Check for errors
	if status != C.errSecSuccess {
		return "", ErrNotFound
	}

	// Create the result
	result := C.GoStringN((*C.char)(passwordData), C.int(passwordDataLength))

	// Cleanup the temporary buffer
	C.SecKeychainItemFreeContent(nil, passwordData)

	// All done
	return result, nil
}

func (*keychainOSX) DeletePassword(service, account string) error {
	// Validate input
	serviceValid := isValidNonNullUTF8(service)
	accountValid := isValidNonNullUTF8(account)
	if !(serviceValid && accountValid) {
		return ErrInvalidValue
	}

	// Convert values to C strings
	serviceCStr := C.CString(service)
	defer C.free(unsafe.Pointer(serviceCStr))
	accountCStr := C.CString(account)
	defer C.free(unsafe.Pointer(accountCStr))

	// Grab the item
	var item C.SecKeychainItemRef
	status := C.SecKeychainFindGenericPassword(
		nil,
		C.UInt32(len(service)),
		serviceCStr,
		C.UInt32(len(account)),
		accountCStr,
		nil,
		nil,
		&item,
	)

	// Check for errors
	if status != C.errSecSuccess {
		return ErrNotFound
	}

	// Delete the item
	status = C.SecKeychainItemDelete(item)

	// Free the item
	C.CFRelease(C.CFTypeRef(item))

	// Check for errors
	if status != C.errSecSuccess {
		return ErrUnknown
	}

	// All done
	return nil
}

func init() {
	// Register the OS X keychain implementation
	keychain = &keychainOSX{}
}
