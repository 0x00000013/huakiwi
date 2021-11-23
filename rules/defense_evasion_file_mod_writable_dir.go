// [metadata]
// creation_date = "2020/04/21"
// maturity = "production"
// updated_date = "2021/03/03"

// [rule]
// author = ["Elastic"]
// description = """
// Identifies file permission modifications in common writable directories by a non-root user. Adversaries often drop files
// or payloads into a writable directory and change permissions prior to execution.
// """
// false_positives = [
//     """
//     Certain programs or applications may modify files or change ownership in writable directories. These can be exempted
//     by username.
//     """,
// ]
// from = "now-9m"
// index = ["auditbeat-*", "logs-endpoint.events.*"]
// language = "kuery"
// license = "Elastic License v2"
// name = "File Permission Modification in Writable Directory"
// risk_score = 21
// rule_id = "9f9a2a82-93a8-4b1a-8778-1780895626d4"
// severity = "low"
// tags = ["Elastic", "Host", "Linux", "Threat Detection", "Defense Evasion"]
// timestamp_override = "event.ingested"
// type = "query"

// query = '''
// event.category:process and event.type:(start or process_started) and
//   process.name:(chmod or chown or chattr or chgrp) and
//   process.working_directory:(/tmp or /var/tmp or /dev/shm) and
//   not user.name:root
// '''

// [[rule.threat]]
// framework = "MITRE ATT&CK"
// [[rule.threat.technique]]
// id = "T1222"
// name = "File and Directory Permissions Modification"
// reference = "https://attack.mitre.org/techniques/T1222/"

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

func defense_evasion_file_mod_writable_dir() error {

	var credSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running defense_evasion_file_mod_writable_dir rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				args_concat := event.Cmd + " " + strings.Join(event.Args, " ")
				if strings.Contains(args_concat, "chmod") || strings.Contains(args_concat, "chown") || strings.Contains(args_concat, "chattr") || strings.Contains(args_concat, "chgrp") {
					if strings.Contains(args_concat, "/tmp") || strings.Contains(args_concat, "/var/tmp") || strings.Contains(args_concat, "/dev/shm") {
						event_json, _ := json.Marshal(event)
						log.Printf("Change Attributes of sensitive directories . Severity: Medium. Details: %s\n", string(event_json))
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

var _ = defense_evasion_file_mod_writable_dir()
