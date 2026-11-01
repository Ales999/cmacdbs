module github.com/ales999/cmacdbs

go 1.26.9

require (
	github.com/ales999/cisaccs/v2 v2.0.0-20261031164104-b3b500c58d8e
	go.etcd.io/bbolt v1.5.0
)

require (
	github.com/alecthomas/kong v1.13.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

replace github.com/ales999/cisaccs/v2 => ../cisaccs/v2
