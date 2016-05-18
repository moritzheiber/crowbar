# oktad

[okta-aws](https://github.com/RedVentures/okta-aws), but in go; more details to follow

## installation

First, install this program:

```sh
$ go get github.com/hopkinsth/oktad
```

Then follow other setup instructions for okta-aws?

## usage

```sh
$ oktad [AWS profile] -- [command]
```

for example

```sh
$ oktad production -- aws ec2 describe-instances
```