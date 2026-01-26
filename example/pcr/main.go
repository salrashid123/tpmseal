package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	tpmseal "github.com/salrashid123/tpmseal"
)

const ()

var (
	tpmPath   = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	pemFile   = flag.String("pemFile", "private.pem", "KeyFile in PEM format")
	key       = flag.String("key", "data to seal", "Data to seal")
	pcrValues = flag.String("pcrValues", "", "PCR Bound value (increasing order, comma separated)")
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

	pcrMap := make(map[uint][]byte)
	for _, v := range strings.Split(*pcrValues, ",") {
		entry := strings.Split(v, ":")
		if len(entry) == 2 {
			uv, err := strconv.ParseUint(entry[0], 10, 32)
			if err != nil {
				fmt.Fprintf(os.Stderr, " PCR key:value is invalid in parsing %s", v)
				return 1
			}
			hexEncodedPCR, err := hex.DecodeString(strings.ToLower(entry[1]))
			if err != nil {
				fmt.Fprintf(os.Stderr, " PCR key:value is invalid in encoding %s", v)
				return 1
			}
			pcrMap[uint(uv)] = hexEncodedPCR
		}
	}

	b, err := tpmseal.Seal(&tpmseal.SealConfig{
		TPMConfig: tpmseal.TPMConfig{
			TPMPath:   *tpmPath,
			TPMDevice: rwc,
		},
		Parent: tpmseal.H2,
		Key:    []byte(*key),
		PcrMap: pcrMap,
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

	keys := make([]uint, 0, len(pcrMap))
	for k := range pcrMap {
		keys = append(keys, k)
	}

	s, err := tpmseal.NewPCRSession(rwr, []tpm2.TPMSPCRSelection{
		{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(keys...),
		},
	}, tpm2.TPM2BDigest{}, 0)
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
