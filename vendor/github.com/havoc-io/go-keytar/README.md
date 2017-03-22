# go-keytar

Cross-platform system keychain access library for Go.

This package is largely based on the
[node-keytar](https://github.com/atom/node-keytar) package, though the GNOME
Keyring implementation has been modified to work on older GNOME versions that
don't provide the simple password storage API.

This package is designed to add, get, replace, and delete passwords in the
user's default keychain.  On OS X, passwords are managed by the Keychain.  On
Linux, passwords are managed by GNOME Keyring.  On Windows, passwords are
managed by Credential Vault.


## Status

The module is currently tested<sup>1</sup> on the following platforms:

| Windows                           | OS X/Linux                             |
| :-------------------------------: | :------------------------------------: |
| [![Windows][win-badge]][win-link] | [![OS X][osx-lin-badge]][osx-lin-link] |

[win-badge]: https://ci.appveyor.com/api/projects/status/aqx64o6ee39ago5o/branch/master?svg=true "AppVeyor build status"
[win-link]:  https://ci.appveyor.com/project/havoc-io/go-keytar/branch/master "AppVeyor build status"
[osx-lin-badge]: https://travis-ci.org/havoc-io/go-keytar.svg?branch=master "Travis CI build status"
[osx-lin-link]:  https://travis-ci.org/havoc-io/go-keytar "Travis CI build status"

<sup>
1: Sadly, the gnome-keyring-daemon does not work on Travis CI, so, while the
library and tests are built on Linux, the tests are not actually run.  If you
want to execute the tests, you'll have to build and run them locally :cry:.
You'll probably have a lot better luck if you do this in a GNOME session.
</sup>


## Dependencies

On each platform, you'll need a Go installation that supports cgo compilation.
On Windows, this means that you'll need MinGW-w64, because MinGW doesn't support
the Windows Credential Vault API and, even if it did, it doesn't support 64-bit
compilation.  On other platforms, Go should just use the system compiler for cgo
compilation.

All library dependencies are met by the system on Windows and OS X.

On Linux, you need to ensure that the GNOME Keyring development package is
installed.  On Ubuntu systems, do:

    sudo apt-get install libgnome-keyring-dev

On Red Hat systems, do:

    sudo yum install gnome-keyring-devel

For all other Linux distributions, consult your package manager.


## Usage

The interface to the platform's default keychain is provided by the `Keychain`
interface.  To get the appropriate `Keychain` instance for the current platform,
do:

	keychain, err := keytar.GetKeychain()
	if err != nil {
		// Handle error (most likely ErrUnsupported)
	}

Then you can add a password:

	// NOTE: AddPassword will not overwrite a password - use
	// keytar.ReplacePassword for that
	err = keychain.AddPassword("example.org", "George", "$eCr37")
	if err != nil {
		// Handle error
	}

Query a password:

	password, err := keychain.GetPassword("example.org", "George")
	if err != nil {
		// Handle error
	}
	// Use password

Replace a password:

	// NOTE: This is a module-level function, not part of the keychain interface
	err = keytar.ReplacePassword(
		keychain,
		"example.org",
		"George",
		"M0r3-$eCr37",
	)
	if err != nil {
		// Handle error
	}

Or delete a password:

	err = keytar.DeletePassword("example.org", "George")
	if err != nil {
		// Handle error (you can probably ignore keytar.ErrNotFound)
	}

That's it.

Note that all strings passed to the interface must be UTF-8 encoded without any
null bytes.  The `GetPassword` method may return a non-UTF-8 string if the entry
was created by another program not enforcing this constraint.


## TODO list

- Create GoDoc entry.
- Move Linux convenience C code out of the Go source file (it's a bit long), or,
  even better, switch to a more modern keychain system on Linux, like libsecret.
- Make APIs try to extract more concise error information from the underlying
  platform APIs.  At the moment, many failures are classified as `ErrUnknown`,
  but we could probably figure out the real error and expand our list of error
  codes.
- Figure out if Go has a secure fallback that we could use somewhere in its
  crypto libraries.
