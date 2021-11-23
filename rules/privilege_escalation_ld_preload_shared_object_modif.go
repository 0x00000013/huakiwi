// [metadata]
// creation_date = "2021/01/27"
// maturity = "production"
// updated_date = "2021/08/03"

// [rule]
// author = ["Elastic"]
// description = """
// Identifies modification of the dynamic linker preload shared object (ld.so.preload). Adversaries may execute malicious
// payloads by hijacking the dynamic linker used to load libraries.
// """
// from = "now-9m"
// index = ["auditbeat-*", "logs-endpoint.events.*"]
// language = "kuery"
// license = "Elastic License v2"
// name = "Modification of Dynamic Linker Preload Shared Object"
// references = [
//     "https://www.anomali.com/blog/rocke-evolves-its-arsenal-with-a-new-malware-family-written-in-golang",
// ]
// risk_score = 47
// rule_id = "717f82c2-7741-4f9b-85b8-d06aeb853f4f"
// severity = "medium"
// tags = ["Elastic", "Host", "Linux", "Threat Detection", "Privilege Escalation"]
// timestamp_override = "event.ingested"
// type = "query"

// query = '''
// event.category:file and not event.type:deletion and file.path:/etc/ld.so.preload
// '''

// [[rule.threat]]
// framework = "MITRE ATT&CK"
// [[rule.threat.technique]]
// id = "T1574"
// name = "Hijack Execution Flow"
// reference = "https://attack.mitre.org/techniques/T1574/"
// [[rule.threat.technique.subtechnique]]
// id = "T1574.006"
// name = "Dynamic Linker Hijacking"
// reference = "https://attack.mitre.org/techniques/T1574/006/"

// [rule.threat.tactic]
// id = "TA0004"
// name = "Privilege Escalation"
// reference = "https://attack.mitre.org/tactics/TA0004/"

package rules

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/mosajjal/ebpf-edr/types"
)

func privilege_escalation_ld_preload_shared_object_modif() error {

	var credSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running privilege_escalation_ld_preload_shared_object_modif rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				args_concat := event.Cmd + " " + strings.Join(event.Args, " ")
				if strings.Contains(args_concat, "/etc/ld.so.preload") {
					event_json, _ := json.Marshal(event)
					log.Printf("Access to ld.so.preload detected. Severity: Medium. Details: %s\n", string(event_json))
				}
			case <-types.GlobalQuit:
				return
				//todo:write quit
			}
		}
	}(credSub)
	return nil
}

var _ = privilege_escalation_ld_preload_shared_object_modif()
