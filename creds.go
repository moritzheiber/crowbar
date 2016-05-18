package main

import "os"
import "io"
import "io/ioutil"
import "errors"
import "encoding/json"
import "fmt"
import "time"
import "syscall"
import "github.com/aws/aws-sdk-go/aws/credentials"

var credsNotFound = errors.New("credentials not found!")
var credsExpired = errors.New("credentials expired!")

type CredStore map[string]AwsCreds
type AwsCreds struct {
	Creds      credentials.Value
	Expiration time.Time
}

// stores credentials in a file
func storeCreds(profile string, creds *credentials.Credentials, expire time.Time) error {
	hdirPath := fmt.Sprintf(
		"%s/%s",
		os.Getenv("HOME"),
		".okta-aws",
	)

	f, err := os.OpenFile(
		fmt.Sprintf(
			"%s/%s",
			hdirPath,
			".credentials",
		),
		os.O_CREATE|os.O_RDWR,
		0600,
	)

	if err != nil {
		return err
	}

	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
	if err != nil {
		// should handle this better
		panic(err)
	}

	var allCreds CredStore
	dec := json.NewDecoder(f)
	err = dec.Decode(&allCreds)

	if err != nil && err != io.EOF {
		return err
	}

	if allCreds == nil {
		allCreds = CredStore{}
	}

	v, err := creds.Get()

	if err != nil {
		return err
	}

	allCreds[profile] = AwsCreds{
		Expiration: expire,
		Creds:      v,
	}

	err = f.Truncate(0)
	if err != nil {
		return err
	}

	b, err := json.Marshal(allCreds)
	if err != nil {
		return err
	}

	_, err = f.Write(b)
	if err != nil {
		return err
	}

	err = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if err != nil {
		return err
	}

	f.Close()

	return nil
}

// tries to load credentials from our credentials file
// returns credsNotFound or credsExpired if it can't
func loadCreds(profile string) (*credentials.Credentials, error) {
	hdirPath := fmt.Sprintf(
		"%s/%s",
		os.Getenv("HOME"),
		".okta-aws",
	)

	b, err := ioutil.ReadFile(
		fmt.Sprintf(
			"%s/%s",
			hdirPath,
			".credentials",
		),
	)
	if err != nil {
		return nil, err
	}

	var allCreds CredStore

	err = json.Unmarshal(b, &allCreds)
	if err != nil {
		return nil, err
	}

	if allCreds == nil {
		return nil, credsNotFound
	}

	creds, ok := allCreds[profile]
	if !ok {
		return nil, credsNotFound
	}

	if time.Now().UnixNano() >= creds.Expiration.UnixNano() {
		return nil, credsExpired
	}

	return credentials.NewStaticCredentials(
		creds.Creds.AccessKeyID,
		creds.Creds.SecretAccessKey,
		creds.Creds.SessionToken,
	), nil
}
