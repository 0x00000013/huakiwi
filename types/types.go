package types

import (
	"encoding/json"
	"os"
	"strings"
)

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

var (
	GlobalEventSubsribers = []*EventSubscriber{}
	GlobalQuit            = make(chan os.Signal, 1)
)

type EventStream struct {
	Pid  uint32            `json:"pid"`
	Gid  uint32            `json:"gid"`
	Cmd  string            `json:"cmd"`
	Args []string          `json:"args"`
	Env  map[string]string `json:"env"`
}

type Event struct {
	Pid    uint32
	Gid    uint32
	ArgLen uint32
	EnvLen uint32
	Cmd    [80]byte
}

func (e EventStream) Keywords() ([]string, bool) {
	return e.Args, true
}

func (e EventStream) Select(s string) (any, bool) {
	switch s {
	case "pid":
		return e.Pid, true
	case "gid":
		return e.Gid, true
	case "cmd":
		return e.Cmd + " " + e.Args[0], true
	case "args":
		return strings.Join(e.Args[1:], " "), true
	case "env":
		return e.Env, true
	case "pwd":
		value, exists := e.Env["PWD"]
		if exists {
			return value, true
		}
		return "", false
	default:
		return nil, false
	}
}

func (e EventStream) Json() string {
	event_json, _ := json.Marshal(e)
	return string(event_json)
}
