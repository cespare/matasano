run: build
	./runner/runner

build:
	cd runner && go build

fmt:
	@gofmt -s -l -w .
