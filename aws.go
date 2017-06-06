package main

import "strings"
import "errors"
import "time"
import "os/user"
import "github.com/tj/go-debug"
import "github.com/aws/aws-sdk-go/aws"
import "github.com/aws/aws-sdk-go/aws/credentials"
import "github.com/aws/aws-sdk-go/aws/session"
import "github.com/aws/aws-sdk-go/service/sts"

var debugAws = debug.Debug("oktad:aws")

// assumes the first role and returns the credentials you need for
// the second assumeRole...
// returns those credentials, the expiration time, and error if any
func assumeFirstRole(acfg AwsConfig, saml *OktaSamlResponse) (*credentials.Credentials, time.Time, error) {
	var emptyExpire time.Time
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
		return nil, emptyExpire, errors.New("no arn found from saml data!")
	}

	parts := strings.Split(arns, ",")

	if len(parts) != 2 {
		return nil, emptyExpire, errors.New("invalid initial role ARN")
	}

	var roleArn, principalArn string
	for _, part := range parts {
		if strings.Contains(part, "saml-provider") {
			principalArn = part
		} else {
			roleArn = part
		}
	}

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
		return nil, emptyExpire, err
	}

	mCreds := credentials.NewStaticCredentials(
		*res.Credentials.AccessKeyId,
		*res.Credentials.SecretAccessKey,
		*res.Credentials.SessionToken,
	)

	return mCreds, *res.Credentials.Expiration, nil
}

// behold, the moment we've been waiting for!
// we need to assume role into the second account...
// this will require the AwsConfig, which includes the final
// destination ARN, and some AWS credentials that allow us to do that
func assumeDestinationRole(acfg AwsConfig, creds *credentials.Credentials) (*credentials.Credentials, time.Time, error) {
	var emptyExpire time.Time
	sess := session.New(
		aws.NewConfig().
			WithRegion(acfg.Region).
			WithCredentials(creds),
	)
	scl := sts.New(
		sess,
	)

	var sessionName string
	if user, err := user.Current(); err == nil {
		sessionName = user.Username
	} else {
		debugAws("error getting username from OS: %s", err)
		sessionName = "unknown-user"
	}

	res, err := scl.AssumeRole(
		&sts.AssumeRoleInput{
			RoleArn:         &acfg.DestArn,
			RoleSessionName: &sessionName,
		},
	)

	if err != nil {
		debugAws("error in assumeDestinationRole! you were so close!")
		return nil, emptyExpire, err
	}

	mCreds := credentials.NewStaticCredentials(
		*res.Credentials.AccessKeyId,
		*res.Credentials.SecretAccessKey,
		*res.Credentials.SessionToken,
	)

	return mCreds, *res.Credentials.Expiration, nil
}
