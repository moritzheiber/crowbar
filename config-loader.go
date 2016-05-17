package main

import "github.com/go-ini/ini"
import "github.com/tj/go-debug"
import "os"
import "fmt"
import "errors"

var badCfgErr = errors.New("Bad configuration file!")

var debugCfg = debug.Debug("oktad:config")

type OktaConfig struct {
	BaseURL string
	AppURL  string
}

// this is what we care about
// in your aws config
type AwsConfig struct {
	// destination ARN
	DestArn string
	Region  string
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

// loads the aws profile file, which we need
// to look up info to assume roles
func loadAwsCfg() (*ini.File, error) {
	return ini.Load(
		fmt.Sprintf(
			"%s/%s",
			os.Getenv("HOME"),
			".aws/config",
		),
	)
}

// reads your AWS config file to load the role ARN
// for a specific profile; returns the ARN and an error if any
func readAwsProfile(name string) (AwsConfig, error) {
	var cfg AwsConfig
	asec, err := loadAwsCfg()
	if err != nil {
		debugCfg("aws profile load err, %s", err)
		return cfg, err
	}

	s, err := asec.GetSection(name)
	if err != nil {
		debugCfg("aws profile read err, %s", err)
		return cfg, err
	}

	if !s.HasKey("role_arn") {
		debugCfg("aws profile %s missing role_arn key", name)
		return cfg, err
	}

	arnKey, _ := s.GetKey("role_arn")
	cfg.DestArn = arnKey.String()

	// try to figure out a region...
	// try to look for a region key in current section
	// if fail: try to look for source_profile
	// if THAT fails, try to load default
	var loadSection string
	if s.HasKey("region") {
		k, _ := s.GetKey("region")
		cfg.Region = k.String()
	} else if s.HasKey("source_profile") {
		k, _ := s.GetKey("source_profile")
		loadSection = k.String()
	} else {
		loadSection = "default"
	}

	if loadSection != "" {
		sec, err := asec.GetSection(loadSection)
		if err == nil {
			if k, err := sec.GetKey("region"); err == nil {
				cfg.Region = k.String()
			}
		}
	}

	// finally, if cfg.region is empty, just use us-east-1
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}

	return cfg, nil
}
