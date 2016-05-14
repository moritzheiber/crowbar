package main

import "fmt"
import "bytes"
import "io"
import "io/ioutil"
import "github.com/tj/go-debug"
import "net/http"

var debugAws = debug.Debug("oktad:okta")

// begins the login process by authenticating
// with okta
func login(cfg OktaConfig, user, pass, destArn string) error {
	debugAws("let the login dance begin")

	pr, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf(
			// TODO: run some checks on this URL
			"%sapi/v1/authn",
			cfg.BaseURL,
		),
		getOktaBody(cfg, user, pass),
	)

	if err != nil {
		debugAws("caught an error building the first request to okta")
		return err
	}

	ajs := "application/json"
	pr.Header.Set("Content-Type", ajs)
	pr.Header.Set("Accept", ajs)

	res, err := http.DefaultClient.Do(pr)
	if err != nil {
		debugAws("caught error on first request to okta")
		return err
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	fmt.Println(string(b))
	return nil
}

// convenience function to get the request body for the okta request
// just need a buffer, man.
// or, really, an io.Reader
func getOktaBody(cfg OktaConfig, user, pass string) io.Reader {
	return bytes.NewBuffer(
		[]byte(
			fmt.Sprintf(
				`
					{
						"username": "%s",
						"password": "%s",
						"options": {
							"multiOptionalFactorEnroll": false,
							"warnBeforePasswordExpired": false
						}
					}
				`,
				user,
				pass,
			),
		),
	)
}
