package main

import (
	"embed"

	log "github.com/sirupsen/logrus"

	sigma "github.com/markuskont/go-sigma-rule-engine"
)

// load all the .yara rules inside the rules/ directory and register them to the stream they subscribe to

//go:embed rules/*.yml
var sigmaRules embed.FS
var RuleSet *sigma.Ruleset

func sigmaInsert() {
	var err error
	RuleSet, err = sigma.NewRuleset(sigma.Config{
		// todo: make this work with embedded FS so we build the rules at compile time rather than runtime (optional)
		Directory: []string{"./rules"},
	})
	if err != nil {
		log.Printf("failed reading rule: %s", err)
	}
	log.Printf("Found %d files, %d ok, %d failed, %d unsupported\n", RuleSet.Total, RuleSet.Ok, RuleSet.Failed, RuleSet.Unsupported)
	for i := 0; i < len(RuleSet.Rules); i++ {
		log.Printf("%v\n", RuleSet.Rules[i].Rule.Title)
	}
}
