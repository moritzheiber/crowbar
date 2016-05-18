package main

import "fmt"

import "github.com/jessevdk/go-flags"
import "github.com/tj/go-debug"
import "github.com/peterh/liner"

func main() {
	var opts struct {
		ConfigFile string `short:"c" long:"config" description:"Path to config file"`
	}

	debug := debug.Debug("oktad:main")
	args, err := flags.Parse(&opts)

	if err != nil {
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
		fmt.Println("You must supply a profile name, sorry.")
		return
	}

	if err != nil {
		fmt.Println("Error reading AWS configuration!")
		return
	}

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
		fmt.Println("Error grabbing temporary credentials!")
		debug("login err %s", err)
		return
	}

	if ores.Status == "MFA_REQUIRED" {
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

		acfg, err := readAwsProfile(
			fmt.Sprintf("profile %s", args[0]),
		)

		if err != nil {
			fmt.Println("Error reading your AWS profile!")
			debug("error was... %s", err)
		}

		mainCreds, err := assumeFirstRole(acfg, saml)
		if err != nil {
			fmt.Println("Error assuming first role!")
			debug("error was %s", err)
			return
		}

		finalCreds, err := assumeDestinationRole(acfg, mainCreds)
		if err != nil {
			fmt.Println("Error assuming second role!")
			debug("error was %s", err)
			return
		}

		// WHOA!
		var cmd string
		var cArgs []string

		if len(args) < 2 {
			fmt.Println("No program specified!")
			return
		}

		for i, a := range args[1:] {
			if a != "--" {
				cmd = a
				if len(args) > (i + 2) {
					cArgs = args[i+2:]
				} else {
					cArgs = []string{}
				}
				break
			}
		}

		err = launch(cmd, cArgs, finalCreds)
		if err != nil {
			debug("caught error from launcher, %s", err)
		}

	} else {
		fmt.Println("MFA required to use this tool.")
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
