# Automation Code Generation
1. If not installed, install Go: https://golang.org/doc/install.
2. If not installed, install `oto` using `go get github.com/pacedotdev/oto`.
This will probably take a minute or two.
3. In the root of auto-processing, run `./generate_code.bat` on Windows or `source generate_code.bat` on Linux (or in Linux emulators like Git Bash).
4. (Optional) Run `gofmt -w ./pkg/avian-api/api.gen.go ./pkg/avian-api/api.gen.go` and `gofmt -w ./pkg/avian-client/avian.gen.go ./pkg/avian-client/avian.gen.go` to format the code.
I don't actually know why the paths are given twice.
This step should probably not be run in GitHub actions as it is useful when humans need to read the code.
