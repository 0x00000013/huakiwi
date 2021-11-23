// [metadata]
// creation_date = "2020/04/17"
// maturity = "production"
// updated_date = "2021/03/03"

// [rule]
// author = ["Elastic"]
// description = "Adversaries may encode/decode data in an attempt to evade detection by host- or network-based security controls."
// false_positives = [
//     """
//     Automated tools such as Jenkins may encode or decode files as part of their normal behavior. These events can be
//     filtered by the process executable or username values.
//     """,
// ]
// from = "now-9m"
// index = ["auditbeat-*", "logs-endpoint.events.*"]
// language = "kuery"
// license = "Elastic License v2"
// name = "Base16 or Base32 Encoding/Decoding Activity"
// risk_score = 21
// rule_id = "debff20a-46bc-4a4d-bae5-5cdd14222795"
// severity = "low"
// tags = ["Elastic", "Host", "Linux", "Threat Detection", "Defense Evasion"]
// timestamp_override = "event.ingested"
// type = "query"

// query = '''
// event.category:process and event.type:(start or process_started) and
//   process.name:(base16 or base32 or base32plain or base32hex)
// '''

// [[rule.threat]]
// framework = "MITRE ATT&CK"
// [[rule.threat.technique]]
// id = "T1140"
// name = "Deobfuscate/Decode Files or Information"
// reference = "https://attack.mitre.org/techniques/T1140/"

// [[rule.threat.technique]]
// id = "T1027"
// name = "Obfuscated Files or Information"
// reference = "https://attack.mitre.org/techniques/T1027/"

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

func defense_evasion_base16_or_base32_encoding_or_decoding_activity() error {

	var credSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running defense_evasion_base16_or_base32_encoding_or_decoding_activity rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				args_concat := event.Cmd + " " + strings.Join(event.Args, " ")
				if strings.Contains(args_concat, "base16") || strings.Contains(args_concat, "base32") || strings.Contains(args_concat, "base32plain") || strings.Contains(args_concat, "base32hex") || strings.Contains(args_concat, "base64") {
					event_json, _ := json.Marshal(event)
					log.Printf("Use of base16/32/64. Severity: Medium. Details: %s\n", string(event_json))

				}
			case <-types.GlobalQuit:
				return
				//todo:write quit
			}
		}
	}(credSub)
	return nil
}

var _ = defense_evasion_base16_or_base32_encoding_or_decoding_activity()
