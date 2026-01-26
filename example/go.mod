module main

go 1.25.1

require github.com/google/go-tpm v0.9.8

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20250520203025-c3c3a4ec1653 // indirect
	github.com/salrashid123/tpm2genkey v0.8.2 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
)

require github.com/salrashid123/tpmseal v0.0.0

replace github.com/salrashid123/tpmseal => ../
