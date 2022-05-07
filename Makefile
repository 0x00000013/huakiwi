OUTPUTFILE=huakiwi.bin
GO_ENV := BPF_CLANG=clang BPF_CFLAGS=""
SOURCES = $(wildcard *.go) $(wildcard */*.go)

$(OUTPUTFILE): $(SOURCES)
	$(GO_ENV) go generate ./...
	$(GO_ENV) go build -o $(OUTPUTFILE) .

clean:
	-rm $(OUTPUTFILE)
	-find . -iname "*.o" -delete
