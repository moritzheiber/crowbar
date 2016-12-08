package main

import "fmt"

import "github.com/jessevdk/go-flags"
import "github.com/tj/go-debug"
import "github.com/peterh/liner"
import "github.com/aws/aws-sdk-go/aws/credentials"
import "time"

const VERSION = "0.6.2"

func main() {
	var opts struct {
		ConfigFile   string `short:"c" long:"config" description:"Path to config file"`
		PrintVersion bool   `short:"v" long:"version" description:"Print version number and exit"`
	}

	debug := debug.Debug("oktad:main")
	args, err := flags.Parse(&opts)

	if err != nil {
		fmt.Println(err)
		return
	}

	if opts.PrintVersion {
		fmt.Printf("oktad v%s\n", VERSION)
		return
	}

	debug("loading configuration data")
	// try to load configuration
	oktaCfg, err := parseConfig(opts.ConfigFile)

	if err != nil {
		fmt.Println("Error reading config file!")
		debug("cfg read err: %s", err)
		return
	}

	if len(args) <= 0 {
		fmt.Println("Hey, that command won't actually do anything.\n\nSorry.")
		return
	}

	awsProfile := args[0]
	acfg, err := readAwsProfile(
		fmt.Sprintf("profile %s", awsProfile),
	)

	var skipSecondRole bool

	if err != nil {
		//fmt.Println("Error reading your AWS profile!")
		debug("error reading AWS profile: %s", err)
		if err == awsProfileNotFound {
			// if the AWS profile isn't found, we'll assume that
			// the user intends to run a command in the first account
			// behind their okta auth, rather than assuming role twice
			skipSecondRole = true
			fmt.Printf(
				"We couldn't find an AWS profile named %s,\nso we will AssumeRole into your base account.\n",
				awsProfile,
			)
			awsProfile = BASE_PROFILE_CREDS

			args = append([]string{BASE_PROFILE_CREDS}, args...)
		}
	}

	maybeCreds, err := loadCreds(awsProfile)
	if err == nil {
		debug("found cached credentials, going to use them")
		// if we could load creds, use them!
		err := prepAndLaunch(args, maybeCreds)
		if err != nil {
			fmt.Println("Error launching program: ", err)
		}
		return
	}

	debug("cred load err %s", err)

	user, pass, err := readUserPass()
	if err != nil {
		// if we got an error here, the user bailed on us
		debug("control-c caught in liner, probably")
		return
	}

	if user == "" || pass == "" {
		fmt.Println("Must supply a username and password!")
		return
	}

	ores, err := login(oktaCfg, user, pass)
	if err != nil {
		fmt.Println("Error authenticating with Okta! Maybe your username or password are wrong.")
		debug("login err %s", err)
		return
	}

	if ores.Status != "MFA_REQUIRED" {
		fmt.Println("MFA required to use this tool.")
		return
	}

	factor, err := extractTokenFactor(ores)

	if err != nil {
		fmt.Println("Error processing okta response!")
		debug("err from extractTokenFactor was %s", err)
		return
	}

	mfaToken, err := readMfaToken()
	if err != nil {
		debug("control-c caught in liner, probably")
		return
	}

	sessionToken, err := doMfa(ores, factor, mfaToken)
	if err != nil {
		fmt.Println("Error performing MFA auth!")
		debug("error from doMfa was %s", err)
		return
	}

	saml, err := getSaml(oktaCfg, sessionToken)
	debug("got saml: \n%s", saml.raw)

	if err != nil {
		fmt.Println("Error preparing to AssumeRole!")
		debug("getSaml err was %s", err)
		return
	}

	mainCreds, mExp, err := assumeFirstRole(acfg, saml)
	if err != nil {
		fmt.Println("Error assuming first role!")
		debug("error was %s", err)
		return
	}

	var finalCreds *credentials.Credentials
	var fExp time.Time
	if !skipSecondRole {
		finalCreds, fExp, err = assumeDestinationRole(acfg, mainCreds)
		if err != nil {
			fmt.Println("Error assuming second role!")
			debug("error was %s", err)
			return
		}
	} else {
		finalCreds = mainCreds
		fExp = mExp
	}

	// all was good, so let's save credentials...
	err = storeCreds(awsProfile, finalCreds, fExp)
	if err != nil {
		debug("err storing credentials, %s", err)
	}

	fmt.Println("Everything looks good; launching your program...")
	err = prepAndLaunch(args, finalCreds)
	if err != nil {
		fmt.Println("Error launching program: ", err)
	}
}

// reads the username and password from the command line
// returns user, then pass, then an error
func readUserPass() (user string, pass string, err error) {
	li := liner.NewLiner()

	// remember to close or weird stuff happens
	defer li.Close()

	li.SetCtrlCAborts(true)
	user, err = li.Prompt("Username: ")
	if err != nil {
		return
	}

	pass, err = li.PasswordPrompt("Password: ")
	if err != nil {
		return
	}

	return
}

// reads and returns an mfa token
func readMfaToken() (string, error) {
	li := liner.NewLiner()
	defer li.Close()
	li.SetCtrlCAborts(true)
	fmt.Println("Your account requires MFA; please enter a token.")
	return li.Prompt("MFA token: ")
}
