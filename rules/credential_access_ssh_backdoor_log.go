// [metadata]
// creation_date = "2020/12/21"
// maturity = "production"
// updated_date = "2021/03/03"

// [rule]
// author = ["Elastic"]
// description = """
// Identifies a Secure Shell (SSH) client or server process creating or writing to a known SSH backdoor log file.
// Adversaries may modify SSH related binaries for persistence or credential access via patching sensitive functions to
// enable unauthorized access or to log SSH credentials for exfiltration.
// """
// false_positives = ["Updates to approved and trusted SSH executables can trigger this rule."]
// from = "now-9m"
// index = ["auditbeat-*", "logs-endpoint.events.*"]
// language = "eql"
// license = "Elastic License v2"
// name = "Potential OpenSSH Backdoor Logging Activity"
// references = [
//     "https://github.com/eset/malware-ioc/tree/master/sshdoor",
//     "https://www.welivesecurity.com/wp-content/uploads/2021/01/ESET_Kobalos.pdf",
// ]
// risk_score = 73
// rule_id = "f28e2be4-6eca-4349-bdd9-381573730c22"
// severity = "high"
// tags = ["Elastic", "Host", "Linux", "Threat Detection", "Persistence", "Credential Access"]
// timestamp_override = "event.ingested"
// type = "eql"

// query = '''
// file where event.type == "change" and process.executable : ("/usr/sbin/sshd", "/usr/bin/ssh") and
//   (
//     file.name : (".*", "~*") or
//     file.extension : ("in", "out", "ini", "h", "gz", "so", "sock", "sync", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9") or
//     file.path :
//     (
//       "/private/etc/*--",
//       "/usr/share/*",
//       "/usr/include/*",
//       "/usr/local/include/*",
//       "/private/tmp/*",
//       "/private/var/tmp/*",
//       "/usr/tmp/*",
//       "/usr/share/man/*",
//       "/usr/local/share/*",
//       "/usr/lib/*.so.*",
//       "/private/etc/ssh/.sshd_auth",
//       "/usr/bin/ssd",
//       "/private/var/opt/power",
//       "/private/etc/ssh/ssh_known_hosts",
//       "/private/var/html/lol",
//       "/private/var/log/utmp",
//       "/private/var/lib",
//       "/var/run/sshd/sshd.pid",
//       "/var/run/nscd/ns.pid",
//       "/var/run/udev/ud.pid",
//       "/var/run/udevd.pid"
//     )
//   )
// '''

// [[rule.threat]]
// framework = "MITRE ATT&CK"
// [[rule.threat.technique]]
// id = "T1556"
// name = "Modify Authentication Process"
// reference = "https://attack.mitre.org/techniques/T1556/"

// [rule.threat.tactic]
// id = "TA0006"
// name = "Credential Access"
// reference = "https://attack.mitre.org/tactics/TA0006/"
// [[rule.threat]]
// framework = "MITRE ATT&CK"
// [[rule.threat.technique]]
// id = "T1554"
// name = "Compromise Client Software Binary"
// reference = "https://attack.mitre.org/techniques/T1554/"

// [rule.threat.tactic]
// id = "TA0003"
// name = "Persistence"
// reference = "https://attack.mitre.org/tactics/TA0003/"

package rules

import (
	"encoding/json"
	"log"
	"path/filepath"

	"github.com/mosajjal/ebpf-edr/types"
)

func credential_access_ssh_backdoor_log() error {

	var suspicious_arguments = []string{
		"/private/etc/*--",
		"/usr/share/*",
		"/usr/include/*",
		"/usr/local/include/*",
		"/private/tmp/*",
		"/private/var/tmp/*",
		"/usr/tmp/*",
		"/usr/share/man/*",
		"/usr/local/share/*",
		"/usr/lib/*.so.*",
		"/private/etc/ssh/.sshd_auth",
		"/usr/bin/ssd",
		"/private/var/opt/power",
		"/private/etc/ssh/ssh_known_hosts",
		"/private/var/html/lol",
		"/private/var/log/utmp",
		"/private/var/lib",
		"/var/run/sshd/sshd.pid",
		"/var/run/nscd/ns.pid",
		"/var/run/udev/ud.pid",
		"/var/run/udevd.pid",
	}

	var credSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running credential_access_ssh_backdoor_log rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				for _, argument := range event.Args {
					for _, arg := range suspicious_arguments {
						if m, _ := filepath.Match(arg, argument); m {
							event_json, _ := json.Marshal(event)
							log.Printf("Potential SSH Backdoor. Severity: High. Details: %s\n", string(event_json))
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

var _ = credential_access_ssh_backdoor_log()
