//[metadata]
// creation_date = "2021/04/12"
// maturity = "production"
// updated_date = "2021/04/12"

// [rule]
// author = ["Elastic"]
// description = """
// Identifies the execution of the EarthWorm tunneler. Adversaries may tunnel network communications to and from a victim
// system within a separate protocol to avoid detection and network filtering, or to enable access to otherwise unreachable systems.
// """
// from = "now-9m"
// index = ["auditbeat-*", "logs-endpoint.events.*"]
// language = "eql"
// license = "Elastic License v2"
// name = "Potential Protocol Tunneling via EarthWorm"
// references = [
//     "http://rootkiter.com/EarthWorm/",
//     "https://decoded.avast.io/luigicamastra/apt-group-targeting-governmental-agencies-in-east-asia/"
// ]
// risk_score = 47
// rule_id = "9f1c4ca3-44b5-481d-ba42-32dc215a2769"
// severity = "medium"
// tags = ["Elastic", "Host", "Linux", "Threat Detection", "Command and Control"]
// timestamp_override = "event.ingested"
// type = "eql"

// query = '''
// process where event.type == "start" and
//  process.args : "-s" and process.args : "-d" and process.args : "rssocks"
// '''

// [[rule.threat]]
// framework = "MITRE ATT&CK"
// [[rule.threat.technique]]
// id = "T1572"
// name = "Protocol Tunneling"
// reference = "https://attack.mitre.org/techniques/T1572/"

// [rule.threat.tactic]
// id = "TA0011"
// name = "Command and Control"
// reference = "https://attack.mitre.org/tactics/TA0011/"

package rules

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/mosajjal/ebpf-edr/types"
)

func command_and_control_tunneling_via_earthworm() error {
	var eSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running command_and_control_tunneling_via_earthworm rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				args_concat := event.Cmd + " " + strings.Join(event.Args, " ")
				if strings.Contains(args_concat, "rssocks") && strings.Contains(args_concat, "-s") && strings.Contains(args_concat, "-d") {
					event_json, _ := json.Marshal(event)
					log.Printf("Earthworm Command and Control detected. Severity: Medium. Details: %s\n", string(event_json))
				}
			case <-types.GlobalQuit:
				return
			}
		}
	}(eSub)
	return nil
}

var _ = command_and_control_tunneling_via_earthworm()
