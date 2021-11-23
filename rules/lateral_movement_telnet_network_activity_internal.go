package rules

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/mosajjal/ebpf-edr/types"
)

func lateral_movement_telnet_network_activity_internal() error {

	var credSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running lateral_movement_telnet_network_activity_internal rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				args_concat := event.Cmd + " " + strings.Join(event.Args, " ")
				if strings.Contains(args_concat, "telnet") ||
					strings.Contains(args_concat, "netcat") || strings.Contains(args_concat, "hping") ||
					strings.Contains(args_concat, "netcat.openbsd") || strings.Contains(args_concat, "nc.openbsd") ||
					strings.Contains(args_concat, "netcat.traditional") || strings.Contains(args_concat, "nping") {
					event_json, _ := json.Marshal(event)
					log.Printf("Use of Generic network tools. Severity: Low. Details: %s\n", string(event_json))
				}
			case <-types.GlobalQuit:
				return
				//todo:write quit
			}
		}
	}(credSub)
	return nil
}

var _ = lateral_movement_telnet_network_activity_internal()
