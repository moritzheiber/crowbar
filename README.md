[![Crate version](https://img.shields.io/crates/v/crowbar)](https://crates.io/crates/crowbar) ![linux-release](https://github.com/moritzheiber/crowbar/workflows/linux-release/badge.svg) ![macos-release](https://github.com/moritzheiber/crowbar/workflows/macos-release/badge.svg) ![windows-release](https://github.com/moritzheiber/crowbar/workflows/windows-release/badge.svg) ![License](https://img.shields.io/crates/l/crowbar)

<img src="images/crowbar-logo-full.svg" width="300">

"**Your trusty tool for retrieving AWS credentials securely via SAML**"

## Quickstart

```
$ crowbar profiles add <profile-name> -u <my-username> -p <idp> --url <idp-app-url>
$ AWS_PROFILE=<profile-name> aws ec2 describe-instances
$ crowbar exec <profile-name> -- aws ec2 describe-instances
```

It'll ask you for your IdP's password and to verify your credential request with [MFA](https://en.wikipedia.org/wiki/Multi-factor_authentication). The credentials you enter are cached securely in your OS keystore.

_Note: Hover over the app that's associated with your AWS account in your IdP's dashboard and copy its link._

## Supported IdPs

- [Okta](https://www.okta.com), with MFA factors Push, TOTP, SMS
  - _Note: the MFA selection screen will present all available methods, however, only Push, TOTP and SMS are implemented at this point_
- [JumpCloud](https://jumpcloud.com), with MFA factor TOTP (Duo is not supported for now)

### Planned

- ADFS

## Installation

### macOS

You can install crowbar via [Homebrew](https://brew.sh):

```sh
$ brew install moritzheiber/tap/crowbar
```

## Windows

You can install crowbar via [Chocolatey](https://chocolatey.org/):

```sh
$ choco install crowbar
```

### Binary releases for all supported operating systems

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
$ cargo install crowbar
```

If you have cargo's binary location in your `PATH` you should be able to run `crowbar` afterwards.

## User guide

### Prerequisites

For crowbar to be useful you have to install the [AWS CLI](https://docs.aws.amazon.com/cli/index.html).

### Adding a profile

You can use `crowbar profiles` to manage profiles:

```
$ crowbar profiles add my-profile -u my-username -p okta --url "https://example.okta.com/example/saml"
```

To get your respective URL, hover over the app that's associated with your AWS account in your Okta dashboard and copy its link. You can strip away the `?fromHome=true` part at the end. Adding the profile using crowbar will also configure the AWS CLI appropriately.

You can also use `crowbar profiles delete <profile-name>` to remove profiles and `crowbar profiles list` to get and overview of all available profiles.

## Usage

### Via AWS profiles

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

### Via an execution environment

You can have crowbar expose your AWS credentials to a process you want to run via environment variables:

```sh
$ crowbar exec <my-profile> -- <your-command-here>
```

For example

```sh
$ crowbar exec super-duper-profile - aws sts get-caller-identity
{
    "Account": "1234567890",
    "UserId": "Some-User:johndoe@example.com",
    "Arn": "arn:aws:sts::1234567890:assumed-role/SuperDuperUser/johndoe@example.com"
}
```

### More options

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

Crowbar's name was formerly used by [an AWS Lambda runtime for Rust emulating a Python library](https://github.com/iliana/rust-crowbar) prior to native runtime support in Lambda. Crowbar 0.1.x and 0.2.x users should move to [the native runtime](https://github.com/awslabs/aws-lambda-rust-runtime).

## TODO

There are a some things still left to do:

### Future

- ~~Add an `exec` mode for tools that don't support the AWS SharedProfileCredentials provider~~
- Support for at least ADFS: As stated before, crowbar is supposed to be a general purpose tool, not just focusing on Okta. ADFS support is mandatory. ~~However, other providers should be considered as well. The code will probably need major re-architecting for this to happen.~~
- Support for WebAuthn: At least Okta supports WebAuthn on the command line and this tool should support it too. This largely depends on the maturity of [the Rust ecosystem around handling FIDO2 security keys](https://github.com/wisespace-io/u2f-rs) though. CTAP2 protocol support is mandatory to work with Okta.
- ~~Focus on cross-platform support: I'm running Linux, all of the code being tested on Linux. I want crowbar to be usable on all major operating systems (Linux, macOS, Windows).~~

### Cosmetic

- Cleaning up the code: This is my first major Rust project, and it shows. The code needs a few other pair of eyes with some more Rust experience.
- Implement some retry logic for MFA challenges? At least the Okta API allows for it in certain conditions
- ~~Error handling is all over the place, including random `panic!` statements and inconsistent logger use. The project needs a proper error handling routine.~~
- ~~Use a role directly if only a single role is provided in the SAML assertion~~
- ~~More consistent UI experience (maybe start looking at other libraries?)~~
