[![Build Status](https://travis-ci.org/jonathanmorley/oktaws.svg?branch=master)](https://travis-ci.org/jonathanmorley/oktaws)
[![Build status](https://ci.appveyor.com/api/projects/status/t78vvs8dmwave53o/branch/master?svg=true)](https://ci.appveyor.com/project/jonathanmorley/oktaws/branch/master)

# oktaws

This program authenticates with Okta, assumes a provided role, and pulls a temporary key with STS to support the role assumption built into the aws cli.

## Installation

Grab a binary for your OS from the [latest release](https://github.com/jonathanmorley/oktaws/releases/latest), and put it somewhere in your PATH. Only supports Windows and MacOS for now!

## Setup

First, create an `~/.oktaws/<OKTA ACCOUNT>.toml` file with the following information:

```
username = '<USERNAME>'
role = '<DEFAULT ROLE>'

[profiles]
profile1 = '<OKTA APPLICATION NAME>'
profile2 = { application = '<OKTA APPLICATION NAME>', role = '<ROLE OVERRIDE>' }
```

The `role` value above is the name (not ARN) of the role you would like to log in as. This can be found when logging into the AWS console through Okta.

The `~/.aws/config` file is read for information, but not modified. It should look similar to the following to link the profile section with the temporary credentials.
See [Assuming a Role](https://docs.aws.amazon.com/cli/latest/userguide/cli-roles.html) for information on configuring the AWS CLI to assume a role.

```
[default]
output = json
region = us-east-1

[profile profile1]
role_arn = arn:aws:iam::MY_ACCOUNT_ID:role/final_role
source_profile = profile1
```

With those set up, you can run `oktaws profile1` to generate keys for a single profile, or just `oktaws` to generate keys for all profiles.

## Usage

```sh
$ oktaws [AWS profile]
$ aws --profile [AWS profile] [command]
```

for example

```sh
$ oktaws production
$ aws --profile production ec2 describe-instances
```

## Debugging

Login didn't work? Use the `-v` flag to emit more verbose logs. Add more `-v`s for increased verbosity:

```sh
$ oktaws production -vv
```

## Contributors

- Jonathan Morley [@jonathanmorley]
