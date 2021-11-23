// [metadata]
// creation_date = "2020/12/22"
// maturity = "production"
// updated_date = "2021/03/03"

// [rule]
// author = ["Elastic"]
// description = """
// Identifies the use of a compression utility to collect known files containing sensitive information, such as credentials
// and system configurations.
// """
// from = "now-9m"
// index = ["auditbeat-*", "logs-endpoint.events.*"]
// language = "kuery"
// license = "Elastic License v2"
// name = "Sensitive Files Compression"
// references = [
//     "https://www.trendmicro.com/en_ca/research/20/l/teamtnt-now-deploying-ddos-capable-irc-bot-tntbotinger.html",
// ]
// risk_score = 47
// rule_id = "6b84d470-9036-4cc0-a27c-6d90bbfe81ab"
// severity = "medium"
// tags = ["Elastic", "Host", "Linux", "Threat Detection", "Collection", "Credential Access"]
// timestamp_override = "event.ingested"
// type = "query"

// query = '''
// event.category:process and event.type:start and
//   process.name:(zip or tar or gzip or hdiutil or 7z) and
//   process.args:
//     (
//       /root/.ssh/id_rsa or
//       /root/.ssh/id_rsa.pub or
//       /root/.ssh/id_ed25519 or
//       /root/.ssh/id_ed25519.pub or
//       /root/.ssh/authorized_keys or
//       /root/.ssh/authorized_keys2 or
//       /root/.ssh/known_hosts or
//       /root/.bash_history or
//       /etc/hosts or
//       /home/*/.ssh/id_rsa or
//       /home/*/.ssh/id_rsa.pub or
//       /home/*/.ssh/id_ed25519 or
//       /home/*/.ssh/id_ed25519.pub or
//       /home/*/.ssh/authorized_keys or
//       /home/*/.ssh/authorized_keys2 or
//       /home/*/.ssh/known_hosts or
//       /home/*/.bash_history or
//       /root/.aws/credentials or
//       /root/.aws/config or
//       /home/*/.aws/credentials or
//       /home/*/.aws/config or
//       /root/.docker/config.json or
//       /home/*/.docker/config.json or
//       /etc/group or
//       /etc/passwd or
//       /etc/shadow or
//       /etc/gshadow
//     )
// '''

// [[rule.threat]]
// framework = "MITRE ATT&CK"
// [[rule.threat.technique]]
// id = "T1552"
// name = "Unsecured Credentials"
// reference = "https://attack.mitre.org/techniques/T1552/"
// [[rule.threat.technique.subtechnique]]
// id = "T1552.001"
// name = "Credentials In Files"
// reference = "https://attack.mitre.org/techniques/T1552/001/"

// [rule.threat.tactic]
// id = "TA0006"
// name = "Credential Access"
// reference = "https://attack.mitre.org/tactics/TA0006/"
// [[rule.threat]]
// framework = "MITRE ATT&CK"
// [[rule.threat.technique]]
// id = "T1560"
// name = "Archive Collected Data"
// reference = "https://attack.mitre.org/techniques/T1560/"
// [[rule.threat.technique.subtechnique]]
// id = "T1560.001"
// name = "Archive via Utility"
// reference = "https://attack.mitre.org/techniques/T1560/001/"

// [rule.threat.tactic]
// id = "TA0009"
// name = "Collection"
// reference = "https://attack.mitre.org/tactics/TA0009/"

package rules

import (
	"encoding/json"
	"log"
	"path/filepath"
	"strings"

	"github.com/mosajjal/ebpf-edr/types"
)

func credential_access_collection_sensitive_files() error {

	var suspicious_arguments = []string{
		"/root/.ssh/id_rsa",
		"/root/.ssh/id_rsa.pub",
		"/root/.ssh/id_ed25519",
		"/root/.ssh/id_ed25519.pub",
		"/root/.ssh/authorized_keys",
		"/root/.ssh/authorized_keys2",
		"/root/.ssh/known_hosts",
		"/root/.bash_history",
		"/etc/hosts",
		"/home/*/.ssh/id_rsa",
		"/home/*/.ssh/id_rsa.pub",
		"/home/*/.ssh/id_ed25519",
		"/home/*/.ssh/id_ed25519.pub",
		"/home/*/.ssh/authorized_keys",
		"/home/*/.ssh/authorized_keys2",
		"/home/*/.ssh/known_hosts",
		"/home/*/.bash_history",
		"/root/.aws/credentials",
		"/root/.aws/config",
		"/home/*/.aws/credentials",
		"/home/*/.aws/config",
		"/root/.docker/config.json",
		"/home/*/.docker/config.json",
		"/etc/group",
		"/etc/passwd",
		"/etc/shadow",
		"/etc/gshadow",
	}

	var credSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running credential_access_collection_sensitive_files rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				args_concat := event.Cmd + " " + strings.Join(event.Args, " ")
				if strings.Contains(args_concat, "zip") || strings.Contains(args_concat, "tar") || strings.Contains(args_concat, "gzip") || strings.Contains(args_concat, "hdiutil") || strings.Contains(args_concat, "7z") || strings.Contains(args_concat, "cat") {
					for _, argument := range event.Args {
						for _, arg := range suspicious_arguments {
							if m, _ := filepath.Match(arg, argument); m {
								event_json, _ := json.Marshal(event)
								log.Printf("Credential Access. Severity: High. Details: %s\n", string(event_json))
								break
							}
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

var _ = credential_access_collection_sensitive_files()
