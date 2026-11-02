module github.com/ales999/cmacdbs

go 1.26.9

require (
	github.com/alecthomas/kong v1.17.0
	github.com/ales999/cisaccs/v2 v2.0.0
	go.etcd.io/bbolt v1.5.0
)

require (
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

replace github.com/ales999/cisaccs/v2 => ../cisaccs/v2
