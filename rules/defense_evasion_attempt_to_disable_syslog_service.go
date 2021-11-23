// [metadata]
// creation_date = "2020/04/27"
// maturity = "production"
// updated_date = "2021/03/03"

// [rule]
// author = ["Elastic"]
// description = """
// Adversaries may attempt to disable the syslog service in an attempt to an attempt to disrupt event logging and evade
// detection by security controls.
// """
// from = "now-9m"
// index = ["auditbeat-*", "logs-endpoint.events.*"]
// language = "kuery"
// license = "Elastic License v2"
// name = "Attempt to Disable Syslog Service"
// risk_score = 47
// rule_id = "2f8a1226-5720-437d-9c20-e0029deb6194"
// severity = "medium"
// tags = ["Elastic", "Host", "Linux", "Threat Detection", "Defense Evasion"]
// timestamp_override = "event.ingested"
// type = "query"

// query = '''
// event.category:process and event.type:(start or process_started) and
//   ((process.name:service and process.args:stop) or
//      (process.name:chkconfig and process.args:off) or
//      (process.name:systemctl and process.args:(disable or stop or kill)))
//   and process.args:(syslog or rsyslog or "syslog-ng")
// '''

// [[rule.threat]]
// framework = "MITRE ATT&CK"
// [[rule.threat.technique]]
// id = "T1562"
// name = "Impair Defenses"
// reference = "https://attack.mitre.org/techniques/T1562/"
// [[rule.threat.technique.subtechnique]]
// id = "T1562.001"
// name = "Disable or Modify Tools"
// reference = "https://attack.mitre.org/techniques/T1562/001/"

// [rule.threat.tactic]
// id = "TA0005"
// name = "Defense Evasion"
// reference = "https://attack.mitre.org/tactics/TA0005/"

package rules

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/mosajjal/ebpf-edr/types"
)

func defense_evasion_attempt_to_disable_syslog_service() error {

	var credSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running defense_evasion_attempt_to_disable_syslog_service rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				args_concat := event.Cmd + " " + strings.Join(event.Args, " ")
				if strings.Contains(args_concat, "service") || strings.Contains(args_concat, "chkconfig") || strings.Contains(args_concat, "systemctl") {
					if strings.Contains(args_concat, "syslog") || strings.Contains(args_concat, "rsyslog") || strings.Contains(args_concat, "syslog-ng") {
						event_json, _ := json.Marshal(event)
						log.Printf("Security Modifications to Syslog service. Severity: High. Details: %s\n", string(event_json))
						break
					}

				}
			case <-types.GlobalQuit:
				return
				//todo:write quit
			}
		}
	}(credSub)
	return nil
}

var _ = defense_evasion_attempt_to_disable_syslog_service()
