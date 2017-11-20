package main

import "github.com/go-ini/ini"
import "github.com/tj/go-debug"
import "os"
import "fmt"
import "errors"

var badCfgErr = errors.New("Could not find a suitable oktaws config file!")
var awsProfileNotFound = errors.New("AWS profile not found!")

var debugCfg = debug.Debug("oktaws:config")

type OktaConfig struct {
	BaseURL string
	AppURL  string
  UserArn string
}

// this is what we care about
// in your aws config
type AwsConfig struct {
	Region  string
}

// loads configuration data from the file specified
func parseConfig(fname string, profile string) (OktaConfig, error) {
	var cfg OktaConfig

	f, err := loadConfig(fname)

	if err != nil {
		return cfg, err
	}

	osec := f.Section("okta")
	if osec == nil {
		return cfg, badCfgErr
	}

  psec := f.Section(profile)
  if psec == nil {
		return cfg, badCfgErr
	}

	if !osec.HasKey("base_url") || !psec.HasKey("app_url") {
		return cfg, badCfgErr
	}

	bu, err := osec.GetKey("base_url")
	if err != nil {
		return cfg, err
	}

	au, err := psec.GetKey("app_url")
	if err != nil {
		return cfg, err
	}

  ua := psec.Key("user_arn")

	cfg.BaseURL = bu.String()
	cfg.AppURL = au.String()
  cfg.UserArn = ua.MustString("")

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
		".oktaws/config",
	)

	debugCfg("trying to load from config param file")
	if _, err := os.Stat(fname); err == nil {
		debugCfg("loading %s", fname)
		f, err := ini.Load(fname)

		if err == nil {
			return f, nil
		}

		debugCfg("error loading %s: %s", fname, err)
	}

	debugCfg("trying to load from CWD")
	if _, err := os.Stat(cwdPath); err == nil {
		debugCfg("loading %s", cwdPath)
		f, err := ini.Load(cwdPath)
		if err == nil {
			return f, nil
		}

		debugCfg("error loading %s: %s", cwdPath, err)
	}

	debugCfg("trying to load from home dir")
	if _, err := os.Stat(hdirPath); err == nil {
		debugCfg("loading %s", hdirPath)

		f, err := ini.Load(hdirPath)
		if err == nil {
			return f, nil
		}

		debugCfg("error loading %s: %s", hdirPath, err)
	}

	return nil, badCfgErr
}

// path to aws credentials file
func findAwsCreds() string {
  return fmt.Sprintf("%s/%s", os.Getenv("HOME"), ".aws/credentials")
}

// loads the aws profile file, which we need
// to look up info to assume roles
func loadAwsCreds() (*ini.File, error) {
	return ini.Load(findAwsCreds())
}

// loads the aws profile file, which we need
// to look up info to assume roles
func saveAwsCreds(config *ini.File) error {
	return config.SaveTo(findAwsCreds())
}

// path to aws config file
func findAwsCfg() string {
  return fmt.Sprintf("%s/%s", os.Getenv("HOME"), ".aws/config")
}

// loads the aws profile file, which we need
// to look up info to assume roles
func loadAwsCfg() (*ini.File, error) {
	return ini.Load(findAwsCfg())
}

// reads your AWS config file to load the role ARN
// for a specific profile; returns the ARN, whether we found your profile,
// and an error if any
func readAwsProfile(profile string) (AwsConfig, error) {
	var cfg AwsConfig
	asec, err := loadAwsCfg()
	if err != nil {
		debugCfg("aws profile load err, %s", err)
		return cfg, err
	}

	s, err := asec.GetSection(profile)
	if err != nil {
		debugCfg("aws profile read err, %s", err)
		return cfg, awsProfileNotFound
	}

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
