// [metadata]
// creation_date = "2020/04/24"
// maturity = "production"
// updated_date = "2021/03/03"

// [rule]
// author = ["Elastic"]
// description = """
// Kernel modules are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the
// functionality of the kernel without the need to reboot the system. This rule identifies attempts to remove a kernel
// module.
// """
// false_positives = [
//     """
//     There is usually no reason to remove modules, but some buggy modules require it. These can be exempted by username.
//     Note that some Linux distributions are not built to support the removal of modules at all.
//     """,
// ]
// from = "now-9m"
// index = ["auditbeat-*", "logs-endpoint.events.*"]
// language = "kuery"
// license = "Elastic License v2"
// name = "Kernel Module Removal"
// references = ["http://man7.org/linux/man-pages/man8/modprobe.8.html"]
// risk_score = 73
// rule_id = "cd66a5af-e34b-4bb0-8931-57d0a043f2ef"
// severity = "high"
// tags = ["Elastic", "Host", "Linux", "Threat Detection", "Defense Evasion"]
// timestamp_override = "event.ingested"
// type = "query"

// query = '''
// event.category:process and event.type:(start or process_started) and
//   process.args:((rmmod and sudo) or (modprobe and sudo and ("--remove" or "-r")))
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
// [[rule.threat]]
// framework = "MITRE ATT&CK"
// [[rule.threat.technique]]
// id = "T1547"
// name = "Boot or Logon Autostart Execution"
// reference = "https://attack.mitre.org/techniques/T1547/"
// [[rule.threat.technique.subtechnique]]
// id = "T1547.006"
// name = "Kernel Modules and Extensions"
// reference = "https://attack.mitre.org/techniques/T1547/006/"

// [rule.threat.tactic]
// id = "TA0003"
// name = "Persistence"
// reference = "https://attack.mitre.org/tactics/TA0003/"

package rules

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/mosajjal/ebpf-edr/types"
)

func defense_evasion_kernel_module_removal() error {

	var credSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running defense_evasion_kernel_module_removal rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				args_concat := event.Cmd + " " + strings.Join(event.Args, " ")
				if (strings.Contains(args_concat, "rmmod")) || (strings.Contains(args_concat, "modprobe") && strings.Contains(args_concat, "-r")) {

					event_json, _ := json.Marshal(event)
					log.Printf("Attempt to remove a kernel module: High. Details: %s\n", string(event_json))

				}

			case <-types.GlobalQuit:
				return
				//todo:write quit
			}
		}
	}(credSub)
	return nil
}

var _ = defense_evasion_kernel_module_removal()
