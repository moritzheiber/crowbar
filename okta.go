package main

import "fmt"
import "bytes"
import "io"
import "io/ioutil"
import "errors"
import "encoding/json"
import "encoding/xml"
import "encoding/base64"
import "github.com/tj/go-debug"
import "github.com/PuerkitoBio/goquery"
import (
	"net/http"
	"github.com/havoc-io/go-keytar"
)

var noMfaError = errors.New("MFA required to use this tool")
var wrongMfaError = errors.New("No valid mfa congfigured for your account!")
var loginFailedError = errors.New("login failed")

var debugOkta = debug.Debug("oktad:okta")

type OktaLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Options  map[string]interface{}
}

type OktaLoginResponse struct {
	ExpiresAt    string
	SessionToken string
	Status       string
	StateToken   string
	Embedded     struct {
		Factors []OktaMfaFactor
	} `json:"_embedded"`
}

type OktaMfaFactor struct {
	Id         string
	FactorType string
	Provider   string
	Status     string
	Links      map[string]HalLink `json:"_links"`
}

type HalLink struct {
	Href string
}

// what the hell XML,
// what the hell.
type OktaSamlResponse struct {
	raw        string
	XMLname    xml.Name `xml:"Response"`
	Attributes []struct {
		Name       string `xml:",attr"`
		NameFormat string `xml:",attr"`
		Value      string `xml:"AttributeValue"`
	} `xml:"Assertion>AttributeStatement>Attribute"`
}

func newLoginRequest(user, pass string) OktaLoginRequest {
	return OktaLoginRequest{
		user,
		pass,
		map[string]interface{}{
			"multiOptionalFactorEnroll": false,
			"warnBeforePasswordExpired": false,
		},
	}
}

// begins the login process by authenticating
// with okta
func login(cfg *OktaConfig, user, pass string) (*OktaLoginResponse, error) {
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
		return nil, err
	}

	ajs := "application/json"
	pr.Header.Set("Content-Type", ajs)
	pr.Header.Set("Accept", ajs)

	res, err := http.DefaultClient.Do(pr)
	if err != nil {
		debugOkta("caught error on first request to okta")
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, loginFailedError
	}

	defer res.Body.Close()
	b, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return nil, err
	}

	debugOkta("login response body %s", string(b))

	var ores OktaLoginResponse
	err = json.Unmarshal(b, &ores)
	if err != nil {
		return nil, err
	}

	return &ores, nil
}

// convenience function to get the request body for the okta request
// just need a buffer, man.
// or, really, an io.Reader
func getOktaLoginBody(cfg *OktaConfig, user, pass string) io.Reader {
	return makeRequestBody(newLoginRequest(user, pass))
}

// turns a thing (a variable of some sort) into an io.Reader for
// reading into a request bodygit
func makeRequestBody(t interface{}) io.Reader {
	debug := debug.Debug("oktad:makeRequestBody")
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	err := enc.Encode(t)
	if err != nil {
		debug("Error encoding json! %s", err)
	}
	return &b
}

// pulls the factor we should use out of the response
func extractTokenFactor(ores *OktaLoginResponse) (*OktaMfaFactor, error) {
	factors := ores.Embedded.Factors
	if len(factors) == 0 {
		return nil, errors.New("MFA factors not present in response")
	}

	var tokenFactor OktaMfaFactor
	for _, factor := range factors {
		// need to assert that this is a map
		// since I don't know the structure enough
		// to make a struct for it
		if factor.FactorType == "token:software:totp" {
			debugOkta("software totp token found!")
			tokenFactor = factor
			break
		}
	}

	if tokenFactor.Id == "" {
		return nil, wrongMfaError
	}

	return &tokenFactor, nil
}

// do that mfa stuff
//
// returns the okta session token and an error if any)
func doMfa(ores *OktaLoginResponse, tf *OktaMfaFactor, mfaToken string) (string, error) {
	var url string
	var st string
	if ores == nil || tf == nil || mfaToken == "" {
		return st, errors.New("invalid params!")
	}

	vObj, ok := tf.Links["verify"]

	if !ok {
		return st, errors.New("Invalid token factor, no 'verify' link found")
	}

	type body struct {
		StateToken string `json:"stateToken"`
		PassCode   string `json:"passCode"`
	}

	url = vObj.Href
	debugOkta("mfa verify url is %s", url)
	req, _ := http.NewRequest(
		"POST",
		url,
		makeRequestBody(body{ores.StateToken, mfaToken}),
	)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := http.DefaultClient.Do(req)

	if err != nil {
		return st, err
	}

	var mfares OktaLoginResponse

	b, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	if err != nil {
		return st, err
	}

	err = json.Unmarshal(b, &mfares)
	if err != nil {
		return st, err
	}

	debugOkta("response body when MFAing was %s", string(b))

	if mfares.Status != "SUCCESS" {
		return st, errors.New("MFA did not succeed!")
	}

	st = mfares.SessionToken

	return st, nil
}

// fetches the SAML we need for AWS round 1
func getSaml(cfg *OktaConfig, sessionToken string) (*OktaSamlResponse, error) {
	res, err := http.Get(
		fmt.Sprintf(
			"%s?%s=%s",
			cfg.AppURL,
			"onetimetoken",
			sessionToken,
		),
	)
	if err != nil {
		return nil, err
	}

	return processSamlResponse(res)

}

func getSamlSession(cfg *OktaConfig, cookie *http.Cookie) (*OktaSamlResponse, error) {

	client := http.Client{}
	req, err := http.NewRequest("GET", cfg.AppURL, nil)
	req.AddCookie(cookie)
	res, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	return processSamlResponse(res)
}

func processSamlResponse(res *http.Response) (*OktaSamlResponse, error) {
	var osres OktaSamlResponse

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return &osres, err
	}

	sel := doc.Find(`input[name="SAMLResponse"]`)

	if sel.Length() < 1 {
		debugOkta("didn't find saml response element")
		return &osres, errors.New("Invalid saml response!")
	}

	saml, ok := sel.First().Attr("value")
	if !ok {
		return &osres, errors.New("Invalid saml response!")
	}

	osres.raw = saml
	b, err := decodeBase64(saml)
	if err != nil {
		debugOkta("error decoding saml base64, %s", err)
		return &osres, err
	}

	err = xml.Unmarshal(b, &osres)
	if err != nil {
		debugOkta("error decoding saml XML, %s", err)
		return &osres, err
	}

	keyStore, err := keytar.GetKeychain()

	if err != nil {
		debugOkta("error getting keychain access %s", err)
	}

	var sessionCookie *http.Cookie

	for _, cookie := range res.Cookies() {
		if cookie.Name == "sid" {
			sessionCookie = cookie
		}
	}
	encCookie, err := encodePasswordStruct(sessionCookie)
	if err != nil {
		fmt.Println("Failed to write cookie to keystore")
		debugOkta("error was %s", err)
	}
	keytar.ReplacePassword(keyStore, APPNAME, SESSION_COOKIE, encCookie)

	return &osres, nil
}

func decodeBase64(b64 string) ([]byte, error) {
	dec := base64.StdEncoding
	return dec.DecodeString(b64)
}
