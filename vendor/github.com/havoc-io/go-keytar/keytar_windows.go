package keytar

// #include <stdlib.h>
// #include <windows.h>
// #include <wincred.h>
import "C"

import (
	// System imports
	"fmt"
	"unsafe"
	"syscall"
)

// Utility function to format service/account into something Windows can store
// AND query.  Credentials actually have a username field, but you can't query
// on it, so it wouldn't allow us to store multiple credentials for the same
// service.
func targetFormat(service, account string) string {
	return fmt.Sprintf("%s@%s", account, service)
}

// keychainWindows implements the Keychain interface on Windows by using the
// Credential Vault infrastructure to store items.
type keychainWindows struct{}

func (*keychainWindows) AddPassword(service, account, password string) error {
	// Validate input
	serviceValid := isValidNonNullUTF8(service)
	accountValid := isValidNonNullUTF8(account)
	passwordValid := isValidNonNullUTF8(password)
	if !(serviceValid && accountValid && passwordValid) {
		return ErrInvalidValue
	}

	// Compute target item name
	target := targetFormat(service, account)

	// Convert the target name.  We require that inputs be in UTF-8, but even
	// then we can't use these using the Windows ANSI (A) APIs, so we have to
	// use the Unicode (W) APIs, but these all use UTF-16, we we need to
	// generate UTF-16 views of our strings.  Fortunately, the Windows syscall
	// package has a nice API for doing this.
	targetUTF16Ptr, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return ErrInvalidValue
	}
	targetUTF16 := C.LPWSTR(unsafe.Pointer(targetUTF16Ptr))

	// Convert the password blob.  This is just stored as a raw array of bytes,
	// so we can store it UTF-8 encoded.
	passwordBlobSize := C.DWORD(len(password))
	passwordVoidBlob := unsafe.Pointer(C.CString(password))
	defer C.free(passwordVoidBlob)
	passwordBlob := C.LPBYTE(passwordVoidBlob)

	// Set up the credential
	var credential C.CREDENTIALW
	credential.Type = C.CRED_TYPE_GENERIC
	credential.TargetName = targetUTF16
	credential.CredentialBlobSize = passwordBlobSize
	credential.CredentialBlob = passwordBlob
	credential.Persist = C.CRED_PERSIST_LOCAL_MACHINE

	// Store the credential
	if C.CredWriteW(&credential, 0) != C.TRUE {
		return ErrUnknown
	}

	// All done
	return nil
}

func (*keychainWindows) GetPassword(service, account string) (string, error) {
	// Validate input
	serviceValid := isValidNonNullUTF8(service)
	accountValid := isValidNonNullUTF8(account)
	if !(serviceValid && accountValid) {
		return "", ErrInvalidValue
	}

	// Compute target item name
	target := targetFormat(service, account)

	// Convert the target name.  See note in AddPassword.
	targetUTF16Ptr, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return "", ErrInvalidValue
	}
	// NOTE: For some reason they use LPCWSTR here, as opposed to LPWSTR in the
	// CREDENTIALW struct
	targetUTF16 := C.LPCWSTR(unsafe.Pointer(targetUTF16Ptr))

	// Query the credential
	var credential C.PCREDENTIALW
	if C.CredReadW(targetUTF16, C.CRED_TYPE_GENERIC, 0, &credential) != C.TRUE {
		return "", ErrNotFound
	}

	// Extract the password blob
	result := C.GoStringN(
		(*C.char)(unsafe.Pointer(credential.CredentialBlob)),
		C.int(credential.CredentialBlobSize),
	)

	// Free the credential memory
	C.CredFree(C.PVOID(credential))

	// All done
	return result, nil
}

func (*keychainWindows) DeletePassword(service, account string) error {
	// Validate input
	serviceValid := isValidNonNullUTF8(service)
	accountValid := isValidNonNullUTF8(account)
	if !(serviceValid && accountValid) {
		return ErrInvalidValue
	}

	// Compute target item name
	target := targetFormat(service, account)

	// Convert the target name.  See note in AddPassword.
	targetUTF16Ptr, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return ErrInvalidValue
	}
	// NOTE: For some reason they use LPCWSTR here, as opposed to LPWSTR in the
	// CREDENTIALW struct
	targetUTF16 := C.LPCWSTR(unsafe.Pointer(targetUTF16Ptr))

	// Delete the credential
	if C.CredDeleteW(targetUTF16, C.CRED_TYPE_GENERIC, 0) != C.TRUE {
		return ErrUnknown
	}

	// All done
	return nil
}

func init() {
	// Register the OS X keychain implementation
	keychain = &keychainWindows{}
}
