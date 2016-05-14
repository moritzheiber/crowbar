package main

import "fmt"
import "bytes"
import "io"
import "io/ioutil"
import "strings"
import "errors"
import "encoding/json"
import "github.com/tj/go-debug"
import "net/http"

var noMfaError = errors.New("MFA required to use this tool")

var debugOkta = debug.Debug("oktad:okta")

// begins the login process by authenticating
// with okta
func login(cfg OktaConfig, user, pass, destArn string) error {
	debugOkta("let the login dance begin")

	pr, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf(
			// TODO: run some checks on this URL
			"%sapi/v1/authn",
			cfg.BaseURL,
		),
		getOktaLoginBody(cfg, user, pass),
	)

	if err != nil {
		debugOkta("caught an error building the first request to okta")
		return err
	}

	ajs := "application/json"
	pr.Header.Set("Content-Type", ajs)
	pr.Header.Set("Accept", ajs)

	res, err := http.DefaultClient.Do(pr)
	if err != nil {
		debugOkta("caught error on first request to okta")
		return err
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	debugOkta("login response body %s", string(b))

	bod := map[string]interface{}{}
	err = json.Unmarshal(b, &bod)
	if err != nil {
		return err
	}

	if pluckStr(bod, "status") != "MFA_REQUIRED" {
		return noMfaError
	}

	err = doMfa(bod)
	if err != nil {
		return err
	}

	return nil
}

// convenience function to get the request body for the okta request
// just need a buffer, man.
// or, really, an io.Reader
func getOktaLoginBody(cfg OktaConfig, user, pass string) io.Reader {
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

// do that mfa stuff
func doMfa(oktaLoginResult map[string]interface{}) error {
	factors := pluckIntSlice(oktaLoginResult, "_embedded.factors")
	if len(factors) == 0 {
		return errors.New("MFA required but no configured factors.")
	}

	var tokenFactor map[string]interface{}
	for _, factor := range factors {
		// need to assert that this is a map
		// since I don't know the structure enough
		// to make a struct for it
		if factor, ok := factor.(map[string]interface{}); ok {
			factorType := pluckStr(factor, "factorType")
			if factorType == "token:software:totp" {
				tokenFactor = factor
			}
		}
	}

	fmt.Println(tokenFactor)
	return nil

}

// like pluck, but only gives you strings
// you'll get an empty string if not found
func pluckStr(o map[string]interface{}, path string) string {
	r := pluck(o, path)
	if r, ok := r.(string); ok {
		return r
	} else {
		return ""
	}
}

// like pluck, but only gives you empty interface slices
// you'll get nil if not found
func pluckIntSlice(o map[string]interface{}, path string) []interface{} {
	r := pluck(o, path)
	if r, ok := r.([]interface{}); ok {
		return r
	} else {
		return nil
	}
}

// given a map, pull a property from it at some deeply nested depth
// this reimplements (most of) JS `pluck` in go: https://github.com/gjohnson/pluck
func pluck(o map[string]interface{}, path string) interface{} {
	// support dots for now ebcause thats all we need
	parts := strings.Split(path, ".")

	if len(parts) == 1 && o[parts[0]] != nil {
		// if there is only one part, just return that property value
		return o[parts[0]]
	} else if len(parts) > 1 && o[parts[0]] != nil {
		var prev map[string]interface{}
		var ok bool
		if prev, ok = o[parts[0]].(map[string]interface{}); !ok {
			// not an object type! ...or a map, yeah, that.
			return nil
		}

		for i := 1; i < len(parts)-1; i += 1 {
			// we need to check the existence of another
			// map[string]interface for every property along the way
			cp := parts[i]

			if prev[cp] == nil {
				// didn't find the property, it's missing
				return nil
			}
			var ok bool
			if prev, ok = prev[cp].(map[string]interface{}); !ok {
				return nil
			}
		}

		if prev[parts[len(parts)-1]] != nil {
			return prev[parts[len(parts)-1]]
		} else {
			return nil
		}
	}

	return nil
}
