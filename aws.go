package main

import "strings"
import "errors"
import "time"
import "github.com/tj/go-debug"
import "github.com/aws/aws-sdk-go/aws"
import "github.com/aws/aws-sdk-go/aws/credentials"
import "github.com/aws/aws-sdk-go/aws/session"
import "github.com/aws/aws-sdk-go/service/sts"

var debugAws = debug.Debug("oktaws:aws")

// assumes the first role and returns the credentials you need for
// the second assumeRole...
// returns those credentials, the expiration time, and error if any
func assumeFirstRole(acfg AwsConfig, ocfg OktaConfig, saml *OktaSamlResponse) (*credentials.Credentials, time.Time, error) {
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

  if (ocfg.UserArn != "") {
    roleArn = ocfg.UserArn
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

  debugAws("error in %s", mCreds)

	return mCreds, *res.Credentials.Expiration, nil
}
