package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	tpmseal "github.com/salrashid123/tpmseal"
)

const ()

var (
	tpmPath     = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	pemFile     = flag.String("pemFile", "private.pem", "KeyFile in PEM format")
	key         = flag.String("key", "data to seal", "Data to seal")
	keypassword = flag.String("keypassword", "foooo", "Data to seal")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	os.Exit(run()) // since defer func() needs to get called first
}

func run() int {

	flag.Parse()
	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		fmt.Printf("can't open TPM %q: %v", *tpmPath, err)
		return 1
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Printf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	b, err := tpmseal.Seal(&tpmseal.SealConfig{
		TPMConfig: tpmseal.TPMConfig{
			TPMPath:     *tpmPath,
			KeyPassword: []byte(*keypassword),
			TPMDevice:   rwc,
		},
		Parent: tpmseal.H2,
		Key:    []byte(*key),
	})
	if err != nil {
		fmt.Printf("error sealing %v\n", err)
		return 1
	}
	fmt.Printf("Sealed Key: \n%s\n", string(b))

	err = os.WriteFile(*pemFile, b, 0644)
	if err != nil {
		fmt.Printf("error creating key file %v\n", err)
		return 1
	}

	s, err := tpmseal.NewPolicyPasswordSession(rwr, []byte(*keypassword), 0)
	if err != nil {
		fmt.Printf("error creating key file %v\n", err)
		return 1
	}
	r, err := tpmseal.Unseal(&tpmseal.UnSealConfig{
		TPMConfig: tpmseal.TPMConfig{
			//TPMPath: *tpmPath,
			TPMDevice: rwc,
		},
		Parent:      tpmseal.H2,
		Key:         b,
		AuthSession: s,
	})
	if err != nil {
		fmt.Printf("error unsealing %v\n", err)
		return 1
	}
	fmt.Printf("unsealed Key: \n%s\n", string(r))

	return 0
}
