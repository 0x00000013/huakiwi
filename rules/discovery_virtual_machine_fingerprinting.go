//[metadata]
// creation_date = "2020/04/27"
// maturity = "production"
// updated_date = "2021/03/03"

// [rule]
// author = ["Elastic"]
// description = """
// An adversary may attempt to get detailed information about the operating system and hardware. This rule identifies
// common locations used to discover virtual machine hardware by a non-root user. This technique has been used by the Pupy
// RAT and other malware.
// """
// false_positives = [
//     """
//     Certain tools or automated software may enumerate hardware information. These tools can be exempted via user name or
//     process arguments to eliminate potential noise.
//     """,
// ]
// from = "now-9m"
// index = ["auditbeat-*", "logs-endpoint.events.*"]
// language = "kuery"
// license = "Elastic License v2"
// name = "Virtual Machine Fingerprinting"
// risk_score = 73
// rule_id = "5b03c9fb-9945-4d2f-9568-fd690fee3fba"
// severity = "high"
// tags = ["Elastic", "Host", "Linux", "Threat Detection", "Discovery"]
// timestamp_override = "event.ingested"
// type = "query"

// query = '''
// event.category:process and event.type:(start or process_started) and
//   process.args:("/sys/class/dmi/id/bios_version" or
//                 "/sys/class/dmi/id/product_name" or
//                 "/sys/class/dmi/id/chassis_vendor" or
//                 "/proc/scsi/scsi" or
//                 "/proc/ide/hd0/model") and
//   not user.name:root
// '''

// [[rule.threat]]
// framework = "MITRE ATT&CK"
// [[rule.threat.technique]]
// id = "T1082"
// name = "System Information Discovery"
// reference = "https://attack.mitre.org/techniques/T1082/"

// [rule.threat.tactic]
// id = "TA0007"
// name = "Discovery"
// reference = "https://attack.mitre.org/tactics/TA0007/"

package rules

import (
	"encoding/json"
	"log"

	"github.com/mosajjal/ebpf-edr/types"
)

func discovery_virtual_machine_fingerprinting() error {

	var suspicious_arguments = []string{
		"/sys/class/dmi/id/bios_version",
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/chassis_vendor",
		"/proc/scsi/scsi",
		"/proc/ide/hd0/model",
	}

	var credSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running discovery_virtual_machine_fingerprinting rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				for _, argument := range event.Args {
					for _, arg := range suspicious_arguments {
						if arg == argument {
							event_json, _ := json.Marshal(event)
							log.Printf("Virtual Machine fingerprinting detected. Severity: Medium. Details: %s\n", string(event_json))
							break
						}
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

var _ = discovery_virtual_machine_fingerprinting()
