// [metadata]
// creation_date = "2020/04/27"
// maturity = "production"
// updated_date = "2021/03/03"

// [rule]
// author = ["Elastic"]
// description = """
// Malware or other files dropped or created on a system by an adversary may leave traces behind as to what was done within
// a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or
// remove them at the end as part of the post-intrusion cleanup process.
// """
// from = "now-9m"
// index = ["auditbeat-*", "logs-endpoint.events.*"]
// language = "kuery"
// license = "Elastic License v2"
// name = "File Deletion via Shred"
// risk_score = 21
// rule_id = "a1329140-8de3-4445-9f87-908fb6d824f4"
// severity = "low"
// tags = ["Elastic", "Host", "Linux", "Threat Detection", "Defense Evasion"]
// timestamp_override = "event.ingested"
// type = "query"

// query = '''
// event.category:process and event.type:(start or process_started) and process.name:shred and
//   process.args:("-u" or "--remove" or "-z" or "--zero")
// '''

// [[rule.threat]]
// framework = "MITRE ATT&CK"
// [[rule.threat.technique]]
// id = "T1070"
// name = "Indicator Removal on Host"
// reference = "https://attack.mitre.org/techniques/T1070/"
// [[rule.threat.technique.subtechnique]]
// id = "T1070.004"
// name = "File Deletion"
// reference = "https://attack.mitre.org/techniques/T1070/004/"

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

func defense_evasion_file_deletion_via_shred() error {
	var credSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running defense_evasion_file_deletion_via_shred rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				args_concat := event.Cmd + " " + strings.Join(event.Args, " ")
				if strings.Contains(args_concat, "shred") && (strings.Contains(args_concat, "--remove") || strings.Contains(args_concat, "--zero") || strings.Contains(args_concat, "-z") || strings.Contains(args_concat, "-u")) {
					event_json, _ := json.Marshal(event)
					log.Printf("Use of Shred utility. Severity: Medium. Details: %s\n", string(event_json))

				}
			case <-types.GlobalQuit:
				return
				//todo:write quit
			}
		}
	}(credSub)
	return nil
}

var _ = defense_evasion_file_deletion_via_shred()
