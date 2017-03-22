# oktad

[okta-aws](https://github.com/RedVentures/okta-aws), but in go. This program authenticates with Okta and then assumes role twice in Amazon.

## Installation

Grab a binary for your OS from the [latest release](https://github.com/hopkinsth/oktad/releases/latest), and put it somewhere in your PATH. Only supports Linux and OSX for now!

If you're on OSX like me, this might be all you need...

```sh
curl -OL https://github.com/RedVentures/oktad/releases/download/v0.6.2/oktad-darwin-amd64
mv oktad-darwin-amd64 /usr/local/bin/oktad
```

## Setup

First, create an `~/.okta-aws/config` file with your Ookta base URL and app URL, like below:

```
[okta]
baseUrl=https://mycompany.okta.com/
appUrl=https://mycompany.okta.com/app/YOUR_APP/OKTA_MAGIC/sso/saml
```

Third, set up an AWS CLI config file. You need to create `~/.aws/config` and fill it with a profile containing the ARN for a role you ultimately want to get temporary credentials for. This file might look like the following:

```
[default]
output = json
region = us-east-1

[profile my_subaccount]
role_arn = arn:aws:iam::MY_ACCOUNT_ID:role/wizards
```

With those things set up, you should be able to run `oktad my_subaccount -- [command]` to run whatever `[command]` is with a set of temporary credentials from Amazon.


## Usage

```sh
$ oktad [AWS profile] -- [command]
```

for example

```sh
$ oktad production -- aws ec2 describe-instances
```

## Debugging

Login didn't work? Launch this program with `DEBUG=oktad*` in your environment for more debugging info:

```sh
$ DEBUG=oktad* oktad production -- aws ec2 describe-instances
```

## Contributors

- Thomas Hopkins [thopkins@redventures.com]
- Lee Standen [@lstanden]
