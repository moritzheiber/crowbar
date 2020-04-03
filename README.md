[![Build Status](https://travis-ci.org/moritzheiber/crowbar.svg?branch=master)](https://travis-ci.org/moritzheiber/crowbar) ![Release](https://github.com/moritzheiber/crowbar/workflows/Release/badge.svg)

<img src="images/crowbar-logo-full.svg" width="300">

"**Your trusty tool for retrieving AWS credentials securely via SAML**"

## Quickstart

```
$ crowbar profiles add <profile-name> -u <my-okta-username> -p okta --url <okta-chicklet-url>
$ AWS_PROFILE=<profile-name> aws ec2 describe-instances
```

It'll ask you for your IdP's password and to verify your credential request with [MFA](https://en.wikipedia.org/wiki/Multi-factor_authentication). The credentials you enter are cashed securely in your OS keystore.

_Note: In Okta you can hover over the chicklet that's associated with your account and copy its link._

## Supported IdPs

- Okta with MFA factors Push, TOTP, SMS
  - _Note: the MFA selection screen will present all available methods, however, only Push, TOTP and SMS are implemented at this point_

### Planned

- ADFS
- Jumpcloud

## Installation

Just download [the latest release](https://github.com/moritzheiber/crowbar/releases) and put it somewhere in your `PATH`. On Linux you'll have to have DBus installed (e.g. the `libdbus-1-3` package on Ubuntu), but most distributions are shipping with DBus pre-installed anyway.

### Compiling your own binary

### Prerequisites

All environments need a **stable** version fo Rust to compile (it might also compile with nightly, but no guarantees). You can use [`rustup`](https://rustup.sh) to install it.

**Linux**

You have to have the DBus development headers (e.g. `libdbus-1-dev` on Ubuntu) installed to compile the crate.

**macOS**

A recent version of [Apple's XCode](https://apps.apple.com/us/app/xcode/id497799835?mt=12).

**Windows**

Rust needs a C++ build environment, which [`rustup`](https://rustup.sh) will help you install and configure.

### Compiling the crate

```sh
$ cargo install --git https://github.com/moritzheiber/crowbar.git crowbar
```

I'm looking into getting the crate published on [crates.io](https://crates.io).

## User guide

### Prerequisites

For crowbar to be useful you have to install the [AWS CLI](https://docs.aws.amazon.com/cli/index.html).

### Adding a profile

You can use `crowbar profiles` to manage profiles:

```
$ crowbar profiles add my-profile -u my-username -p okta --url "https://example.com/example/saml"
```

Adding the profile using crowbar will also configure the AWS CLI appropriately.

You can also use `crowbar delete <profile-name>` to remove profiles and `crowbar list` to get and overview of all available profiles.

## Usage

You can now run any command that requires AWS credentials while having the profile name exported in your shell:

```sh
$ AWS_PROFILE=my-profile aws ec2 --region us-east-1 describe-instances
```

or, on Windows:

```shell
$ set AWS_PROFILE=my-profile
$ aws ec2 --region us-east-1 describe-instances
```

This will automatically authenticate you with your IdP, ask for your MFA, if needed, and the present you with a selection of roles you're able to assume to get temporary AWS credentials. If there is just one role to assume crowbar will skip the selection and directly use it for fetching credentials.

### On the command line

You can obviously also run crowbar directly:

```sh
$ crowbar creds [PROFILE]
```

for example:

```sh
$ crowbar creds my-profile
```

For further information please consult `crowbar --help` or `crowbar creds --help`.

## FAQ

**Why does the `credential_process` command added to the CLI configuration look so weird?**

The `sh` workaround is needed because the AWS CLI captures `stderr` without forwarding it to the child process. crowbar uses `stderr` to ask for your IdP password, your selection of MFA and, if there are more than one, your selection of role to assume. [There's an open issue](https://github.com/boto/botocore/issues/1348#issue-284285273) and [several](https://github.com/boto/botocore/pull/1349) [PRs](https://github.com/boto/botocore/pull/1835). If you want to see this issue solved please show them some love.

## History

Crowbar is designed to securely retrieve temporary AWS credentials using its STS service, utilizing SAML as a means for authenticating and authorizing requests. Its unique feature is that it doesn't write any sensitive data (passwords, session tokens, security keys) to disk, but rather stores them in the operating system's keystore which requires the user's consent to have them retrieved from.

It is meant to be used with the [AWS CLI's `credential_process` capabilities](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html), to provide a seamless experience when it comes to using AWS resources on the command line.

Crowbar is a fork of [oktaws](https://github.com/jonathanmorley/oktaws), written by [Jonathan Morley](@jonathanmorley), whereas the main differentiating factors for forking the original project were that it does write credentials to disk and it focuses solely on Okta. Both of these are not the intentions of this project.

For the time being, only Okta is supported as an IdP, with other providers (ADFS being prioritized the highest) to be added as soon as capacity allows.

## TODO

There are a some things still left to do:

### Future

- Add an `exec` mode for tools that don't support the AWS SharedProfileCredentials provider
- Support for at least ADFS: As stated before, crowbar is supposed to be a general purpose tool, not just focusing on Okta. ADFS support is mandatory. However, other providers should be considered as well. The code will probably need major re-architecting for this to happen.
- Support for WebAuthn: At least Okta supports WebAuthn on the command line and this tool should support it too. This largely depends on the maturity of [the Rust ecosystem around handling U2F/FIDO2 security keys](https://github.com/wisespace-io/u2f-rs) though.
- Focus on cross-platform support: I'm running Linux, all of the code being tested on Linux. I want crowbar to be usable on all major operating systems (Linux, macOS, Windows).

### Cosmetic

- Cleaning up the code: This is my first major Rust project, and it shows. The code needs a few other pair of eyes with some more Rust experience.
- Implement some retry logic for MFA challenges? At least the Okta API allows for it in certain conditions
- ~~Error handling is all over the place, including random `panic!` statements and inconsistent logger use. The project needs a proper error handling routine.~~
- ~~Use a role directly if only a single role is provided in the SAML assertion~~
- ~~More consistent UI experience (maybe start looking at other libraries?)~~
