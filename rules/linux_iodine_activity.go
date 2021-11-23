package rules

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/mosajjal/ebpf-edr/types"
)

func linux_iodine_activity() error {

	var credSub types.EventSubscriber

	go func(s types.EventSubscriber) {
		log.Println("Running linux_iodine_activity rule")
		s.Source = make(chan types.EventStream, 100)
		s.Subscribe()
		for {
			select {
			case event := <-s.Source:
				args_concat := event.Cmd + " " + strings.Join(event.Args, " ")
				if strings.Contains(args_concat, "iodine") || strings.Contains(args_concat, "iodined") {

					event_json, _ := json.Marshal(event)
					log.Printf("iodine DNS tunneling process name detected. Severity: High. Details: %s\n", string(event_json))

				}
			case <-types.GlobalQuit:
				return
				//todo:write quit
			}
		}
	}(credSub)
	return nil
}

var _ = linux_iodine_activity()
