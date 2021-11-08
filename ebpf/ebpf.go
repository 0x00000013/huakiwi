package ebpf

import "github.com/cilium/ebpf"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ./bpf/execsnoop.c -- -I./include

// export the useful functions out of the generated file
func CreateEmptyObject() bpfObjects {
	return bpfObjects{}
}

func LoadObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return loadBpfObjects(obj, opts)
}
