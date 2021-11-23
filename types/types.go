package types

import "os"

type EventSubscriber struct {
	Source chan EventStream
}

type EventSub interface {
	Subscribe() error
	run() error
}

func (e EventSubscriber) Subscribe() error {
	GlobalEventSubsribers = append(GlobalEventSubsribers, &e)
	return nil
}

var GlobalEventSubsribers = []*EventSubscriber{}
var GlobalQuit = make(chan os.Signal, 1)

type EventStream struct {
	Pid  uint32            `json:"pid"`
	Gid  uint32            `json:"gid"`
	Cmd  string            `json:"cmd"`
	Args []string          `json:"args"`
	Env  map[string]string `json:"env"`
}
