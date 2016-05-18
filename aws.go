package main

import "strings"
import "errors"
import "github.com/tj/go-debug"
import "github.com/aws/aws-sdk-go/aws"
import "github.com/aws/aws-sdk-go/aws/credentials"
import "github.com/aws/aws-sdk-go/aws/session"
import "github.com/aws/aws-sdk-go/service/sts"

var debugAws = debug.Debug("oktad:aws")

// assumes the first role and returns the credentials you need for
// the second assumeRole...
func assumeFirstRole(acfg AwsConfig, saml *OktaSamlResponse) (*credentials.Credentials, error) {
	sess := session.New(
		aws.NewConfig().WithRegion(acfg.Region),
	)
	scl := sts.New(
		sess,
	)

	var arns string

	for _, a := range saml.Attributes {
		if a.Name == "https://aws.amazon.com/SAML/Attributes/Role" {
			arns = a.Value
			debugAws("found principal ARN %s", a.Value)
			break
		}
	}

	if arns == "" {
		return nil, errors.New("no arn found from saml data!")
	}

	parts := strings.Split(arns, ",")
	roleArn, principalArn := parts[0], parts[1]

	res, err := scl.AssumeRoleWithSAML(
		&sts.AssumeRoleWithSAMLInput{
			PrincipalArn:    &principalArn,
			RoleArn:         &roleArn,
			SAMLAssertion:   &saml.raw,
			DurationSeconds: aws.Int64(3600),
		},
	)

	if err != nil {
		debugAws("error in AssumeRoleWithSAML")
		return nil, err
	}

	mCreds := credentials.NewStaticCredentials(
		*res.Credentials.AccessKeyId,
		*res.Credentials.SecretAccessKey,
		*res.Credentials.SessionToken,
	)

	return mCreds, nil
}

// behold, the moment we've been waiting for!
// we need to assume role into the second account...
// this will require the AwsConfig, which includes the final
// destination ARN, and some AWS credentials that allow us to do that
func assumeDestinationRole(acfg AwsConfig, creds *credentials.Credentials) (*credentials.Credentials, error) {
	sess := session.New(
		aws.NewConfig().
			WithRegion(acfg.Region).
			WithCredentials(creds),
	)
	scl := sts.New(
		sess,
	)

	res, err := scl.AssumeRole(
		&sts.AssumeRoleInput{
			RoleArn:         &acfg.DestArn,
			RoleSessionName: aws.String("fromRvMain"),
		},
	)

	if err != nil {
		debugAws("error in assumeRole! you were so close!")
		return nil, err
	}

	mCreds := credentials.NewStaticCredentials(
		*res.Credentials.AccessKeyId,
		*res.Credentials.SecretAccessKey,
		*res.Credentials.SessionToken,
	)

	return mCreds, nil
}
