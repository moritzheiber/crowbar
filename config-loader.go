package main

import "github.com/go-ini/ini"
import "os"
import "fmt"
import "errors"

var badCfgErr = errors.New("Bad configuration file!")

type OktaConfig struct {
	BaseURL string
	AppURL  string
}

// loads configuration data from the file specified
func loadConfig(fname string) (OktaConfig, error) {
	var cfg OktaConfig
	cwd, _ := os.Getwd()
	hdir := os.Getenv("HOME")

	f, err := ini.LooseLoad(
		fname,
		fmt.Sprintf("%s/%s", cwd, ".okta"),
		fmt.Sprintf("%s/%s", hdir, ".okta-aws/config"),
	)

	if err != nil {
		return cfg, err
	}

	osec := f.Section("okta")
	if osec == nil {
		return cfg, badCfgErr
	}

	if !osec.HasKey("baseUrl") || !osec.HasKey("appUrl") {
		return cfg, badCfgErr
	}

	bu, err := osec.GetKey("baseUrl")
	if err != nil {
		return cfg, err
	}

	au, err := osec.GetKey("appUrl")
	if err != nil {
		return cfg, err
	}

	cfg.BaseURL = bu.String()
	cfg.AppURL = au.String()

	return cfg, nil
}
