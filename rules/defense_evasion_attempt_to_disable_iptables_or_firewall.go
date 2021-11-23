// [metadata]
// creation_date = "2020/04/24"
// maturity = "production"
// updated_date = "2021/03/03"

// [rule]
// author = ["Elastic"]
// description = """
// Adversaries may attempt to disable the iptables or firewall service in an attempt to affect how a host is allowed to
// receive or send network traffic.
// """
// from = "now-9m"
// index = ["auditbeat-*", "logs-endpoint.events.*"]
// language = "kuery"
// license = "Elastic License v2"
// name = "Attempt to Disable IPTables or Firewall"
// risk_score = 47
// rule_id = "125417b8-d3df-479f-8418-12d7e034fee3"
// severity = "medium"
// tags = ["Elastic", "Host", "Linux", "Threat Detection", "Defense Evasion"]
// timestamp_override = "event.ingested"
// type = "query"

// query = '''
// event.category:process and event.type:(start or process_started) and
//   process.name:ufw and process.args:(allow or disable or reset) or

//   (((process.name:service and process.args:stop) or
//      (process.name:chkconfig and process.args:off) or
//      (process.name:systemctl and process.args:(disable or stop or kill))) and
//    process.args:(firewalld or ip6tables or iptables))
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

func defense_evasion_attempt_to_disable_iptables_or_firewall() error {

	var credSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running defense_evasion_attempt_to_disable_iptables_or_firewall rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				args_concat := event.Cmd + " " + strings.Join(event.Args, " ")
				if strings.Contains(args_concat, "service") || strings.Contains(args_concat, "chkconfig") || strings.Contains(args_concat, "systemctl") {
					if strings.Contains(args_concat, "firewalld") || strings.Contains(args_concat, "ip6tables") || strings.Contains(args_concat, "iptables") || strings.Contains(args_concat, "ufw") {
						event_json, _ := json.Marshal(event)
						log.Printf("Security Modifications to Firewall service. Severity: High. Details: %s\n", string(event_json))
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

var _ = defense_evasion_attempt_to_disable_iptables_or_firewall()
