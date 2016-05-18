package main

import "os"
import "fmt"
import "os/exec"
import "github.com/tj/go-debug"
import "github.com/aws/aws-sdk-go/aws/credentials"

var debugLaunch = debug.Debug("oktad:launch")

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
