# oktaws

This program authenticates with Okta, assumes a provided role, and pulls a temporary key with STS to then support the role assumption built into the aws cli.

## Installation

Grab a binary for your OS from the [latest release](https://github.com/jonathanmorley/oktaws/releases/latest), and put it somewhere in your PATH. Only supports Linux and OSX for now!

If you're on OSX like me, this might be all you need...

```sh
curl -L -o /usr/local/bin/oktaws https://github.com/jonathanmorley/oktaws/releases/download/`curl -v 'https://github.com/jonathanmorley/oktaws/releases/latest' 2>&1 | grep Location | grep -E -o 'v[0-9]+\.[0-9]+\.[0-9]+'`/oktaws-darwin-amd64 && chmod +x /usr/local/bin/oktaws
```

## Setup

First, create an `~/.oktaws/config` file with your Okta base URL, app URL and user ARN, like below:

```
[aws_profile_name]
organization = mycompany
app_id = YOUR_APP/OKTA_MAGIC
role = arn:aws:iam::MY_ACCOUNT_ID:role/initial_role

```https://cvent.okta.com/home/amazon_aws/0oa86lj5jeUdzcbz70x7/272?fromHome=true

The `role` value above is the ARN of the Role you would like to log in as. This can be found in the Roles section of the IAM service of your account.

You can find the other values above by going to your Identity Provider in the IAM service of your AWS account and downloading the metadata.
The metadata will contain some `<md:SingleSignOnService>` elements, where the `Location` attribute will look like https://mycompany.okta.com/app/YOUR_APP/OKTA_MAGIC/sso/saml"
The parts of this URL will correspond to the values above.

Second, ensure that the `~/.aws/credentials` file does not contain important information under the `aws_profile_name` section, as they will be overwritten with temporary credentials. This file might look like the following:

```
[aws_profile_name]
aws_access_key_id     = REDACTED
aws_secret_access_key = REDACTED
aws_session_token     = REDACTED
```

The `~/.aws/config` file is read for information, but not modified. It should look similar to the following to link the profile section with the temporary credentials.

```
[default]
output = json
region = us-east-1

[profile aws_profile_name]
role_arn = arn:aws:iam::MY_ACCOUNT_ID:role/final_role
source_profile = aws_profile_name
```

With those things set up, you should be able to run `oktaws aws_profile_name`

## Usage

```sh
$ oktaws [AWS profile]
$ aws [command]
```

for example

```sh
$ oktaws production
$ aws ec2 describe-instances
```

## Debugging

Login didn't work? Launch this program with `DEBUG=oktaws*` in your environment for more debugging info:

```sh
$ RUST_LOG=oktaws=debug oktaws production
```

## Contributors

- Jonathan Morley [@jonathanmorley]
