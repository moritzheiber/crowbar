package main

import "github.com/go-ini/ini"
import "github.com/tj/go-debug"
import "os"
import "fmt"
import "errors"

var badCfgErr = errors.New("Bad configuration file!")

var debugCfg = debug.Debug("config")

type OktaConfig struct {
	BaseURL string
	AppURL  string
}

// loads configuration data from the file specified
func parseConfig(fname string) (OktaConfig, error) {
	var cfg OktaConfig

	f, err := loadConfig(fname)

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

//figures out which config to load
func loadConfig(fname string) (*ini.File, error) {
	cwd, _ := os.Getwd()

	cwdPath := fmt.Sprintf(
		"%s/%s",
		cwd,
		".okta",
	)

	hdirPath := fmt.Sprintf(
		"%s/%s",
		os.Getenv("HOME"),
		".okta-aws/config",
	)

	debugCfg("trying to load from config param file")
	if _, err := os.Stat(fname); err == nil {
		debugCfg("loading %s", fname)
		return ini.Load(fname)
	}

	debugCfg("trying to load from CWD")
	if _, err := os.Stat(cwdPath); err == nil {
		debugCfg("loading %s", cwdPath)
		return ini.Load(cwdPath)
	}

	debugCfg("trying to load from home dir")
	if _, err := os.Stat(hdirPath); err == nil {
		debugCfg("loading %s", hdirPath)
		return ini.Load(hdirPath)
	}

	return nil, badCfgErr
}
