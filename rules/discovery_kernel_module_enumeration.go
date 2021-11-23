// [metadata]
// creation_date = "2020/04/23"
// maturity = "production"
// updated_date = "2021/03/03"

// [rule]
// author = ["Elastic"]
// description = """
// Loadable Kernel Modules (or LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They
// extend the functionality of the kernel without the need to reboot the system. This identifies attempts to enumerate
// information about a kernel module.
// """
// false_positives = [
//     """
//     Security tools and device drivers may run these programs in order to enumerate kernel modules. Use of these programs
//     by ordinary users is uncommon. These can be exempted by process name or username.
//     """,
// ]
// from = "now-9m"
// index = ["auditbeat-*", "logs-endpoint.events.*"]
// language = "kuery"
// license = "Elastic License v2"
// name = "Enumeration of Kernel Modules"
// risk_score = 47
// rule_id = "2d8043ed-5bda-4caf-801c-c1feb7410504"
// severity = "medium"
// tags = ["Elastic", "Host", "Linux", "Threat Detection", "Discovery"]
// timestamp_override = "event.ingested"
// type = "query"

// query = '''
// event.category:process and event.type:(start or process_started) and
//   process.args:(kmod and list and sudo or sudo and (depmod or lsmod or modinfo))
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
	"strings"

	"github.com/mosajjal/ebpf-edr/types"
)

func discovery_kernel_module_enumeration() error {

	var credSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running discovery_kernel_module_enumeration rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				args_concat := event.Cmd + " " + strings.Join(event.Args, " ")
				if (strings.Contains(args_concat, "kmod") && strings.Contains(args_concat, "list")) || strings.Contains(args_concat, "depmod") || strings.Contains(args_concat, "lsmod") || strings.Contains(args_concat, "modinfo") {
					event_json, _ := json.Marshal(event)
					log.Printf("Kernel module enumeration detected. Severity: Medium. Details: %s\n", string(event_json))

				}
			case <-types.GlobalQuit:
				return
				//todo:write quit
			}
		}
	}(credSub)
	return nil
}

var _ = discovery_kernel_module_enumeration()
