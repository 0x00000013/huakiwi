package rules

type EarthWorm struct {
	Name        string
	Uuid        string
	Description string
	Feed        chan *Event
	Result      chan *Event
}

func (ew EarthWorm) Init() {
	ew.Name = "earthworm"
	ew.Uuid = "9f1c4ca3-44b5-481d-ba42-32dc215a2769"
	ew.Description = `
	[metadata]
	creation_date = "2021/04/12"
	maturity = "production"
	updated_date = "2021/04/12"

	[rule]
	author = ["Elastic"]
	description = """
	Identifies the execution of the EarthWorm tunneler. Adversaries may tunnel network communications to and from a victim
	system within a separate protocol to avoid detection and network filtering, or to enable access to otherwise unreachable systems.
	"""
	from = "now-9m"
	index = ["auditbeat-*", "logs-endpoint.events.*"]
	language = "eql"
	license = "Elastic License v2"
	name = "Potential Protocol Tunneling via EarthWorm"
	references = [
		"http://rootkiter.com/EarthWorm/",
		"https://decoded.avast.io/luigicamastra/apt-group-targeting-governmental-agencies-in-east-asia/"
	]
	risk_score = 47
	rule_id = "9f1c4ca3-44b5-481d-ba42-32dc215a2769"
	severity = "medium"
	tags = ["Elastic", "Host", "Linux", "Threat Detection", "Command and Control"]
	timestamp_override = "event.ingested"
	type = "eql"

	[[rule.threat]]
	framework = "MITRE ATT&CK"
	[[rule.threat.technique]]
	id = "T1572"
	name = "Protocol Tunneling"
	reference = "https://attack.mitre.org/techniques/T1572/"

	[rule.threat.tactic]
	id = "TA0011"
	name = "Command and Control"
	reference = "https://attack.mitre.org/tactics/TA0011/"
	`
}

// verdict function determines if the event is a match for this rule
func (EarthWorm) verdict() bool {
	return true, nil
}

func (ew EarthWorm) Exec() error {
	for {
		select {
		case <-ew.Feed:
			if ew.verdict() {
				ew.Result <- e.Feed
			}
		}
	}
	return nil

}
