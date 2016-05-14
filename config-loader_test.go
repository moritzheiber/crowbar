package main

import "testing"
import "os"
import "io/ioutil"

func TestLoadConfigBadFiles(t *testing.T) {
	os.Setenv("HOME", "/tmp")

	if _, err := parseConfig("badfile"); err == nil {
		t.Log("Config loading should have errored on a bad path!")
		t.Fail()
	}
}

func TestLoadConfigFromSpecifiedFile(t *testing.T) {
	err := ioutil.WriteFile(
		"tmp-sample",
		[]byte(`
			[okta]
			baseUrl=https://awebsite.com
			appUrl=https://awebsite.com/stuff
		`),
		0644,
	)
	if err != nil {
		t.Log("Error creating test file")
		t.Fail()
	}

	if cfg, err := parseConfig("tmp-sample"); err == nil {
		if cfg.BaseURL != "https://awebsite.com" ||
			cfg.AppURL != "https://awebsite.com/stuff" {
			t.Log("Config not properly parsed!", cfg)
			t.Fail()
		}
	} else {
		t.Log("Error reading file", err)
		t.Fail()
	}

	err = os.Remove("tmp-sample")
	if err != nil {
		t.Log("Error removing temporary file tmp-sample...")
	}
}
