package main

import "os"
import "fmt"
import "errors"
import "os/exec"
import "github.com/tj/go-debug"
import "github.com/aws/aws-sdk-go/aws/credentials"

var debugLaunch = debug.Debug("oktaws:launch")

// runs some program
func launch(cmd string, args []string, creds *credentials.Credentials) error {
	debugLaunch("launching program %s with args %s", cmd, args)
	e := exec.Command(
		cmd,
		args...,
	)

	cv, err := creds.Get()
	if err != nil {
		fmt.Println("wtf, ", err)
		return err
	}

	e.Stderr = os.Stderr
	e.Stdout = os.Stdout
	e.Stdin = os.Stdin
	e.Env = append(e.Env, os.Environ()...)

	envVarFmt := "%s=%s"
	e.Env = append(
		e.Env,
		fmt.Sprintf(envVarFmt, "AWS_SESSION_TOKEN", cv.SessionToken),
		fmt.Sprintf(envVarFmt, "AWS_ACCESS_KEY_ID", cv.AccessKeyID),
		fmt.Sprintf(envVarFmt, "AWS_SECRET_ACCESS_KEY", cv.SecretAccessKey),
	)

	return e.Run()
}

// prepares arguments for launching & then does it
// expected input includes arguments from the command line once the program name
// (in this case ./oktaws) is removed
// and then AWS credentials to put in the environment of the launched program
func prepAndLaunch(args []string, creds *credentials.Credentials) error {
	// WHOA!
	var cmd string
	var cArgs []string

	if len(args) < 2 {
		return errors.New("No program specified!")

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

	err := launch(cmd, cArgs, creds)
	if err != nil {
		debugLaunch("caught error from launcher, %s", err)
	}

	return err
}
