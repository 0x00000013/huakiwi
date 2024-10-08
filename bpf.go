//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/mosajjal/ebpf-edr/ebpf"
)

func execsnoopTrace(stopper chan os.Signal) {
	const mapKey uint32 = 0
	// Name of the kernel function to trace.
	fn := "sys_execve"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := ebpf.CreateEmptyObject()
	if err := ebpf.LoadObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe(fn, objs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	ticker := time.NewTicker(time.Second)

	for {
		select {
		case <-ticker.C:
			var value uint64
			if err := objs.KprobeMap.Lookup(mapKey, &value); err != nil {
				log.Fatalf("reading map: %v", err)
			}
			log.Printf("called %d times\n", value)
		case <-stopper:
			return
		}
	}
}

func eventExecv(stopper chan os.Signal, events chan EventStream) {
	// Name of the kernel function to trace.
	fn := "sys_enter_execve"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := ebpf.CreateEmptyObject()
	if err := ebpf.LoadObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Tracepoint("syscalls", fn, objs.TraceExecveEvent, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	rd, _ := perf.NewReader(objs.Events, os.Getpagesize())
	defer rd.Close()
	var event InputEvent

	for {
		var output EventStream
		output.Env = make(map[string]string)

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event entry into an Event structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}
		var i uint32
		for i = 0; i < event.ArgLen; i++ {
			argv, err := objs.Argvs.LookupBytes(i)
			if err != nil {
				log.Printf("reading argv: %s", err)
				break
			}
			if argv != nil {
				output.Args = append(output.Args, string(unix.ByteSliceToString(argv[:])))
			}
		}
		for i = 0; i < event.EnvLen; i++ {
			var env []byte
			env, err = objs.Envs.LookupBytes(i)
			if err != nil {
				log.Printf("reading argv: %s", err)
				break
			}
			if env != nil {
				envString := string(string(unix.ByteSliceToString(env[:])))
				k, v := strings.Split(envString, "=")[0], strings.Split(envString, "=")[1]
				output.Env[k] = v
			}
		}
		output.Pid = event.Pid
		output.Gid = event.Gid
		output.Cmd = string(unix.ByteSliceToString(event.Cmd[:]))

		events <- output

	}
}
