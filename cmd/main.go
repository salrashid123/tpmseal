package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"

	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/salrashid123/tpmseal"
)

const ()

var (
	help          = flag.Bool("help", false, "print usage")
	mode          = flag.String("mode", "", "seal | unseal")
	parentKeyType = flag.String("parentKeyType", "h2", "rsa_ek|ecc_ek|rsa_srk|ecc_srk|h2 (default h2)")
	keyName       = flag.String("keyName", "", "User defined description of the key to export")
	pcrValues     = flag.String("pcrValues", "", "PCR Bound value (increasing order, comma separated)")
	secret        = flag.String("secret", "", "secret to seal")
	key           = flag.String("key", "", "TPM file to unseal")
	out           = flag.String("out", "", "File to write the unsealed data to (default: stdout)")
	// pubout  = flag.String("pubout", "/tmp/pub.bin", "(optional) File to write the tpm2_tools compatible public part")
	// privout = flag.String("privout", "/tmp/priv.bin", "(optional) File to write the tpm2_tools compatible private part")
	tpmPath  = flag.String("tpm-path", "/dev/tpmrm0", "Create: Path to the TPM device (character device or a Unix socket).")
	password = flag.String("password", "", "Password for the created key")
	ownerpw  = flag.String("ownerpw", "", "Owner Password for the created key")
	// persistentHandle       = flag.Uint("persistentHandle", 0x81008001, "persistentHandle to save the key to (default 0x81008001 persistent)")
	// parentpersistentHandle = flag.Uint("parentpersistentHandle", 0, "persistentHandle to save the key to (default 0 persistent)")
	version           = flag.Bool("version", false, "print version")
	Commit, Tag, Date string
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
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

	if *help {
		flag.PrintDefaults()
		return 0
	}

	if *version {
		// go build  -ldflags="-s -w -X main.Tag=$(git describe --tags --abbrev=0) -X main.Commit=$(git rev-parse HEAD)" cmd/main.go
		fmt.Fprintf(os.Stdout, "Version: %s\n", Tag)
		fmt.Fprintf(os.Stdout, "Date: %s\n", Date)
		fmt.Fprintf(os.Stdout, "Commit: %s\n", Commit)
		return 0
	}

	if *mode != "seal" && *mode != "unseal" {
		fmt.Fprintf(os.Stderr, "--mode must be either seal or unseal got  %s", *mode)
		return 1
	}
	rwc, err := openTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "can't open TPM : %v", err)
		return 1
	}
	defer rwc.Close()

	rwr := transport.FromReadWriter(rwc)

	// // get the endorsement key for the local TPM which we will use for parameter encryption
	sessionEncryptionRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth([]byte(*ownerpw)),
		},
		InPublic: tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating EK Primary  %v", err)
		return 1
	}
	defer func() {
		_, _ = tpm2.FlushContext{
			FlushHandle: sessionEncryptionRsp.ObjectHandle,
		}.Execute(rwr)
	}()

	keyType := tpmseal.H2
	switch *parentKeyType {
	case "h2":
		keyType = tpmseal.H2
	case "rsa_srk":
		keyType = tpmseal.RSASRK
	case "ecc_srk":
		keyType = tpmseal.ECCSRK
	case "rsa_ek":
		keyType = tpmseal.RSAEK
	case "ec_ek":
		keyType = tpmseal.ECCEK
	default:
		fmt.Fprintf(os.Stderr, "unknwon parentkey type  %s", *parentKeyType)
		return 1
	}

	switch *mode {
	case "seal":
		var sealedBytes []byte

		if *pcrValues != "" {

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

			sealedBytes, err = tpmseal.Seal(&tpmseal.SealConfig{
				TPMConfig: tpmseal.TPMConfig{
					TPMDevice:               rwc,
					KeyPassword:             []byte(*password),
					Ownerpassword:           []byte(*ownerpw),
					SessionEncryptionHandle: sessionEncryptionRsp.ObjectHandle,
				},
				Parent: keyType,
				Key:    []byte(*secret),
				PcrMap: pcrMap,
			})
			if err != nil {
				fmt.Printf("error sealing %v\n", err)
				return 1
			}

		} else if *password != "" {
			sealedBytes, err = tpmseal.Seal(&tpmseal.SealConfig{
				TPMConfig: tpmseal.TPMConfig{
					TPMDevice:               rwc,
					KeyPassword:             []byte(*password),
					Ownerpassword:           []byte(*ownerpw),
					SessionEncryptionHandle: sessionEncryptionRsp.ObjectHandle,
				},
				Name:   *keyName,
				Parent: keyType,
				Key:    []byte(*secret),
			})
			if err != nil {
				fmt.Printf("error sealing %v\n", err)
				return 1
			}
		} else {
			sealedBytes, err = tpmseal.Seal(&tpmseal.SealConfig{
				TPMConfig: tpmseal.TPMConfig{
					TPMDevice:               rwc,
					Ownerpassword:           []byte(*ownerpw),
					SessionEncryptionHandle: sessionEncryptionRsp.ObjectHandle,
				},
				Parent: keyType,
				Key:    []byte(*secret),
			})
			if err != nil {
				fmt.Printf("error sealing %v\n", err)
				return 1
			}
		}

		if *out != "" {
			err = os.WriteFile(*out, sealedBytes, 0644)
			if err != nil {
				fmt.Printf("error creating key file %v\n", err)
				return 1
			}
		} else {
			fmt.Printf("%s", sealedBytes)
		}

	case "unseal":

		k, err := os.ReadFile(*key)
		if err != nil {
			fmt.Printf("error reading key %v\n", err)
			return 1
		}

		var outbytes []byte

		if *pcrValues != "" {

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

			keys := make([]uint, 0, len(pcrMap))
			for k := range pcrMap {
				keys = append(keys, k)
			}

			s, err := tpmseal.NewPCRSession(rwr, []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(keys...),
				},
			}, tpm2.TPM2BDigest{}, sessionEncryptionRsp.ObjectHandle)
			if err != nil {
				fmt.Printf("error creating key file %v\n", err)
				return 1
			}

			r, err := tpmseal.Unseal(&tpmseal.UnSealConfig{
				TPMConfig: tpmseal.TPMConfig{
					//TPMPath: *tpmPath,
					TPMDevice:               rwc,
					Ownerpassword:           []byte(*ownerpw),
					SessionEncryptionHandle: sessionEncryptionRsp.ObjectHandle,
				},
				Parent:      keyType,
				Key:         k,
				AuthSession: s,
			})
			if err != nil {
				fmt.Printf("error unsealing %v\n", err)
				return 1
			}
			outbytes = r
		} else if *password != "" {
			s, err := tpmseal.NewPolicyPasswordSession(rwr, []byte(*password), sessionEncryptionRsp.ObjectHandle)
			if err != nil {
				fmt.Printf("error creating key file %v\n", err)
				return 1
			}

			r, err := tpmseal.Unseal(&tpmseal.UnSealConfig{
				TPMConfig: tpmseal.TPMConfig{
					//TPMPath: *tpmPath,
					TPMDevice:               rwc,
					Ownerpassword:           []byte(*ownerpw),
					SessionEncryptionHandle: sessionEncryptionRsp.ObjectHandle,
				},
				Parent:      keyType,
				Key:         k,
				AuthSession: s,
			})
			if err != nil {
				fmt.Printf("error unsealing %v\n", err)
				return 1
			}
			outbytes = r
		} else {

			r, err := tpmseal.Unseal(&tpmseal.UnSealConfig{
				TPMConfig: tpmseal.TPMConfig{
					//TPMPath: *tpmPath,
					TPMDevice:               rwc,
					Ownerpassword:           []byte(*ownerpw),
					SessionEncryptionHandle: sessionEncryptionRsp.ObjectHandle,
				},
				Parent: keyType,
				Key:    k,
			})
			if err != nil {
				fmt.Printf("error unsealing %v\n", err)
				return 1
			}
			outbytes = r
		}
		if *out != "" {
			err = os.WriteFile(*out, outbytes, 0644)
			if err != nil {
				fmt.Printf("error creating key file %v\n", err)
				return 1
			}
		} else {
			fmt.Printf("%s", outbytes)
		}
	}
	return 0
}
