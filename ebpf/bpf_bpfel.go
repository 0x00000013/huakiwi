// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *bpfObjects
//     *bpfPrograms
//     *bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	KprobeExecve          *ebpf.ProgramSpec `ebpf:"kprobe_execve"`
	TraceExecveEvent      *ebpf.ProgramSpec `ebpf:"trace_execve_event"`
	UretprobeBashReadline *ebpf.ProgramSpec `ebpf:"uretprobe_bash_readline"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	Argvs     *ebpf.MapSpec `ebpf:"argvs"`
	Envs      *ebpf.MapSpec `ebpf:"envs"`
	Events    *ebpf.MapSpec `ebpf:"events"`
	KprobeMap *ebpf.MapSpec `ebpf:"kprobe_map"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	Argvs     *ebpf.Map `ebpf:"argvs"`
	Envs      *ebpf.Map `ebpf:"envs"`
	Events    *ebpf.Map `ebpf:"events"`
	KprobeMap *ebpf.Map `ebpf:"kprobe_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.Argvs,
		m.Envs,
		m.Events,
		m.KprobeMap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	KprobeExecve          *ebpf.Program `ebpf:"kprobe_execve"`
	TraceExecveEvent      *ebpf.Program `ebpf:"trace_execve_event"`
	UretprobeBashReadline *ebpf.Program `ebpf:"uretprobe_bash_readline"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.KprobeExecve,
		p.TraceExecveEvent,
		p.UretprobeBashReadline,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed bpf_bpfel.o
var _BpfBytes []byte
