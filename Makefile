.DEFAULT: test
.PHONY:   test
test:
	go test -timeout 10000ms -cover -race github.com/cloudcopper/core/encoding/tlv
