package main

import "bytes"
import "errors"
import "fmt"
import "time"
import "encoding/base64"
import "encoding/gob"
import "github.com/tj/go-debug"
import "github.com/aws/aws-sdk-go/aws/credentials"
import "github.com/havoc-io/go-keytar"

var debugCredStore = debug.Debug("oktad:credStore")
var credsNotFound = errors.New("credentials not found!")
var credsExpired = errors.New("credentials expired!")

const APPNAME = "oktad"
const BASE_PROFILE_CREDS = "__oktad_base_credentials"

type CredStore map[string]AwsCreds
type AwsCreds struct {
	Creds      credentials.Value
	Expiration time.Time
}


// stores credentials in a file
func storeCreds(profile string, creds *credentials.Credentials, expire time.Time) error {

	keyStore, err := keytar.GetKeychain()
	if (err != nil) {
		debugCredStore("unable to instantiate keychain storage")
		return err
	}

	v, err := creds.Get()
	if err != nil {
		debugCredStore("failed to read aws creds")
		return err
	}
	res, err := encodePasswordStruct(v)
	if err != nil {
		debugCredStore("failed to encode password");
	}

	err = keytar.ReplacePassword(keyStore, APPNAME, profile, res)

	if (err != nil) {
		debugCredStore("failed to store password to keychain")
		return err
	}

	return nil
}

// tries to load credentials from our credentials file
// returns credsNotFound or credsExpired if it can't
func loadCreds(profile string) (*credentials.Credentials, error) {

	keyStore, err := keytar.GetKeychain()

	if (err != nil) {
		debugCredStore("unable to instantiate keychain storage")
		return nil, err
	}

	passwordB64, err := keyStore.GetPassword(APPNAME, profile)
	if (err != nil) {
		debugCredStore(fmt.Sprintf("no credentials found for supplied profile: %s", profile))
		return nil, credsNotFound;
	}
	creds := AwsCreds{}
	err = decodePasswordStruct(&creds, passwordB64)
	if err != nil {
		return nil, credsNotFound
	}

	if (time.Now().UnixNano() >= creds.Expiration.UnixNano()) {
		return nil, credsExpired
	}

	return credentials.NewStaticCredentials(
		creds.Creds.AccessKeyID,
		creds.Creds.SecretAccessKey,
		creds.Creds.SessionToken,
	), nil
}


func encodePasswordStruct(in interface{}) (string, error) {
	b := bytes.Buffer{}
	enc := gob.NewEncoder(&b)
	enc.Encode(in)
	encString := base64.StdEncoding.EncodeToString(b.Bytes())
	return encString, nil
}

func decodePasswordStruct(out interface{}, in string) (error) {

	b, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(b)
	dec := gob.NewDecoder(buf)
	err = dec.Decode(out)

	if err != nil {
		debugCredStore("failed to decode creds from keystore")
		debug.Debug("oktad:decodePasswordStruct")("error was %s", err)
		return err
	}

	return nil
}
