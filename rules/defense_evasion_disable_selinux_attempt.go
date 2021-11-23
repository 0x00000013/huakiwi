// [metadata]
// creation_date = "2020/04/22"
// maturity = "production"
// updated_date = "2021/03/03"

// [rule]
// author = ["Elastic"]
// description = """
// Identifies potential attempts to disable Security-Enhanced Linux (SELinux), which is a Linux kernel security feature to
// support access control policies. Adversaries may disable security tools to avoid possible detection of their tools and
// activities.
// """
// from = "now-9m"
// index = ["auditbeat-*", "logs-endpoint.events.*"]
// language = "kuery"
// license = "Elastic License v2"
// name = "Potential Disabling of SELinux"
// risk_score = 47
// rule_id = "eb9eb8ba-a983-41d9-9c93-a1c05112ca5e"
// severity = "medium"
// tags = ["Elastic", "Host", "Linux", "Threat Detection", "Defense Evasion"]
// timestamp_override = "event.ingested"
// type = "query"

// query = '''
// event.category:process and event.type:(start or process_started) and process.name:setenforce and process.args:0
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

func defense_evasion_disable_selinux_attempt() error {

	var credSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running defense_evasion_disable_selinux_attempt rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				args_concat := event.Cmd + " " + strings.Join(event.Args, " ")
				if strings.Contains(args_concat, "setenforce") && strings.Contains(args_concat, "0") {
					event_json, _ := json.Marshal(event)
					log.Printf("SELinux Disabled. Severity: Medium. Details: %s\n", string(event_json))

				}
			case <-types.GlobalQuit:
				return
				//todo:write quit
			}
		}
	}(credSub)
	return nil
}

var _ = defense_evasion_disable_selinux_attempt()
