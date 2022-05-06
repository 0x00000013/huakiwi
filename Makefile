OUTPUTFILE=huakiwi.bin

# $BPF_CLANG -cflags $BPF_CFLAGS 

go_env := BPF_CLANG=clang BPF_CFLAGS=""
go:
	$(go_env) go generate ./...
	$(go_env) go build -o $(OUTPUTFILE) .

.PHONY: all
all: go

clean:
	rm -v -f $(OUTPUTFILE)
	rm -v bpf_bpfe*
