// [metadata]
// creation_date = "2020/04/15"
// maturity = "production"
// updated_date = "2021/03/03"

// [rule]
// author = ["Elastic"]
// description = """
// Identifies when a terminal (tty) is spawned via Python. Attackers may upgrade a simple reverse shell to a fully
// interactive tty after obtaining initial access to a host.
// """
// from = "now-9m"
// index = ["auditbeat-*", "logs-endpoint.events.*"]
// language = "kuery"
// license = "Elastic License v2"
// name = "Interactive Terminal Spawned via Python"
// risk_score = 73
// rule_id = "d76b02ef-fc95-4001-9297-01cb7412232f"
// severity = "high"
// tags = ["Elastic", "Host", "Linux", "Threat Detection", "Execution"]
// timestamp_override = "event.ingested"
// type = "query"

// query = '''
// event.category:process and event.type:(start or process_started) and process.name:python and
//   process.args:("import pty; pty.spawn(\"/bin/sh\")" or
//                 "import pty; pty.spawn(\"/bin/dash\")" or
//                 "import pty; pty.spawn(\"/bin/bash\")")
// '''

// [[rule.threat]]
// framework = "MITRE ATT&CK"
// [[rule.threat.technique]]
// id = "T1059"
// name = "Command and Scripting Interpreter"
// reference = "https://attack.mitre.org/techniques/T1059/"

// [rule.threat.tactic]
// id = "TA0002"
// name = "Execution"
// reference = "https://attack.mitre.org/tactics/TA0002/"

package rules

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/mosajjal/ebpf-edr/types"
)

func execution_python_tty_shell() error {

	var credSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running execution_python_tty_shell rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				args_concat := event.Cmd + " " + strings.Join(event.Args, " ")
				if strings.Contains(args_concat, "python") && (strings.Contains(args_concat, "/bin/bash") || strings.Contains(args_concat, "/bin/dash") || strings.Contains(args_concat, "/bin/sh")) {

					event_json, _ := json.Marshal(event)
					log.Printf("Python Trying to execute Shell. Severity: High. Details: %s\n", string(event_json))

				}
			case <-types.GlobalQuit:
				return
				//todo:write quit
			}
		}
	}(credSub)
	return nil
}

var _ = execution_python_tty_shell()
