package main

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
)

func main() {
	// Subscribe to signals for terminating the program.
	signal.Notify(GlobalQuit, os.Interrupt, syscall.SIGTERM)
	log.Println("Waiting for events..")

	events := make(chan EventStream)
	go eventExecv(GlobalQuit, events)

	// todo: transform the events to have group name and username as well as the IDs by grabbing the groups and users periodically
	sigmaInsert()

	for {
		select {
		case event := <-events:
			results, match := RuleSet.EvalAll(event)
			if match {
				log.Warnf("%+s", Alarm{Rule: results, Event: event}.Json())
			}

		case <-GlobalQuit:
			log.Println("Received SIGTERM, exiting..")
			return
		}
	}
}
