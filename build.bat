oto -template generate/templates/server.go.plush -out pkg/avian-api/api.gen.go -pkg api ./generate
oto -template generate/templates/client.go.plush -out pkg/avian-client/avian.gen.go -pkg avian ./generate
gofmt -w ./pkg/avian-api/api.gen.go ./pkg/avian-api/api.gen.go
gofmt -w ./pkg/avian-client/avian.gen.go ./pkg/avian-client/avian.gen.go
go build cmd/avian/avian.go
