package tpmseal

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

const (
	swTPMPath = "127.0.0.1:2321"
)

var ()

const ()

func TestNoPolicy(t *testing.T) {

	dataToSeal := "somesecret"

	b, err := Seal(&SealConfig{
		TPMConfig: TPMConfig{
			TPMPath: swTPMPath,
		},
		Parent: H2,
		Key:    []byte(dataToSeal),
	})
	require.NoError(t, err)

	r, err := Unseal(&UnSealConfig{
		TPMConfig: TPMConfig{
			TPMPath: swTPMPath,
		},
		Parent: H2,
		Key:    b,
	})
	require.NoError(t, err)
	require.Equal(t, []byte(dataToSeal), r)
}

func TestKeySize(t *testing.T) {

	tests := []struct {
		name     string
		keySize  int
		soudFail bool
	}{
		{"test_small", 32, false},
		{"test_max", 128, false},
		{"test_large", 129, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			key := make([]byte, tc.keySize)
			rand.Read(key)

			b, err := Seal(&SealConfig{
				TPMConfig: TPMConfig{
					TPMPath: swTPMPath,
				},
				Parent: H2,
				Key:    key,
			})
			if tc.soudFail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				r, err := Unseal(&UnSealConfig{
					TPMConfig: TPMConfig{
						TPMPath: swTPMPath,
					},
					Parent: H2,
					Key:    b,
				})
				if tc.soudFail {
					require.Error(t, err)
				}
				require.NoError(t, err)
				require.Equal(t, key, r)

			}

		})
	}

}

func TestKeyTypes(t *testing.T) {

	dataToSeal := "somesecret"
	tests := []struct {
		name    string
		keytype ParentType
	}{
		{"rsasrk", RSASRK},
		{"eccsrk", ECCSRK},
		{"rsaek", RSAEK},
		{"eccek", ECCEK},
		{"h2", H2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := Seal(&SealConfig{
				TPMConfig: TPMConfig{
					TPMPath: swTPMPath,
				},
				Parent: tc.keytype,
				Key:    []byte(dataToSeal),
			})
			require.NoError(t, err)

			r, err := Unseal(&UnSealConfig{
				TPMConfig: TPMConfig{
					TPMPath: swTPMPath,
				},
				Parent: tc.keytype,
				Key:    b,
			})
			require.NoError(t, err)

			require.Equal(t, []byte(dataToSeal), r)
		})
	}
}

func TestDevice(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	dataToSeal := "somesecret"

	b, err := Seal(&SealConfig{
		TPMConfig: TPMConfig{
			TPMDevice: tpmDeviceB,
		},
		Parent: H2,
		Key:    []byte(dataToSeal),
	})
	require.NoError(t, err)

	r, err := Unseal(&UnSealConfig{
		TPMConfig: TPMConfig{
			TPMDevice: tpmDeviceB,
		},
		Parent: H2,
		Key:    b,
	})
	require.NoError(t, err)

	require.Equal(t, []byte(dataToSeal), r)

}

func TestPassword(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwr := transport.FromReadWriter(tpmDeviceB)

	dataToSeal := "somesecret"
	passphrase := "somepassword"

	b, err := Seal(&SealConfig{
		TPMConfig: TPMConfig{
			TPMDevice:   tpmDeviceB,
			KeyPassword: []byte(passphrase),
		},
		Parent: H2,
		Key:    []byte(dataToSeal),
	})
	require.NoError(t, err)
	s, err := NewPolicyPasswordSession(rwr, []byte(passphrase), 0)
	defer tpmDeviceB.Close()
	r, err := Unseal(&UnSealConfig{
		TPMConfig: TPMConfig{
			TPMDevice: tpmDeviceB,
		},
		Parent:      H2,
		Key:         b,
		AuthSession: s,
	})
	require.NoError(t, err)

	require.Equal(t, []byte(dataToSeal), r)

}

func TestPCR(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwr := transport.FromReadWriter(tpmDeviceB)

	dataToSeal := "somesecret"

	pcrValues := "23:0000000000000000000000000000000000000000000000000000000000000000"

	pcrMap := make(map[uint][]byte)
	for _, v := range strings.Split(pcrValues, ",") {
		entry := strings.Split(v, ":")
		if len(entry) == 2 {
			uv, err := strconv.ParseUint(entry[0], 10, 32)
			require.NoError(t, err)
			hexEncodedPCR, err := hex.DecodeString(strings.ToLower(entry[1]))
			require.NoError(t, err)
			pcrMap[uint(uv)] = hexEncodedPCR
		}
	}

	b, err := Seal(&SealConfig{
		TPMConfig: TPMConfig{
			TPMDevice: tpmDeviceB,
		},
		Parent: H2,
		Key:    []byte(dataToSeal),
		PcrMap: pcrMap,
	})
	require.NoError(t, err)

	keys := make([]uint, 0, len(pcrMap))
	for k := range pcrMap {
		keys = append(keys, k)
	}

	s, err := NewPCRSession(rwr, []tpm2.TPMSPCRSelection{
		{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(keys...),
		},
	}, tpm2.TPM2BDigest{}, 0)
	defer tpmDeviceB.Close()
	r, err := Unseal(&UnSealConfig{
		TPMConfig: TPMConfig{
			TPMDevice: tpmDeviceB,
		},
		Parent:      H2,
		Key:         b,
		AuthSession: s,
	})
	require.NoError(t, err)

	require.Equal(t, []byte(dataToSeal), r)

}

func TestPCRFail(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwr := transport.FromReadWriter(tpmDeviceB)

	dataToSeal := "somesecret"

	pcrValues := "23:0000000000000000000000000000000000000000000000000000000000000000"

	pcrMap := make(map[uint][]byte)
	for _, v := range strings.Split(pcrValues, ",") {
		entry := strings.Split(v, ":")
		if len(entry) == 2 {
			uv, err := strconv.ParseUint(entry[0], 10, 32)
			require.NoError(t, err)
			hexEncodedPCR, err := hex.DecodeString(strings.ToLower(entry[1]))
			require.NoError(t, err)
			pcrMap[uint(uv)] = hexEncodedPCR
		}
	}

	keys := make([]uint, 0, len(pcrMap))
	for k := range pcrMap {
		keys = append(keys, k)
	}

	b, err := Seal(&SealConfig{
		TPMConfig: TPMConfig{
			TPMDevice: tpmDeviceB,
		},
		Parent: H2,
		Key:    []byte(dataToSeal),
		PcrMap: pcrMap,
	})
	require.NoError(t, err)

	pcrReadRsp, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(keys...),
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(uint(23)),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  pcrReadRsp.PCRValues.Digests[0].Buffer,
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	s, err := NewPCRSession(rwr, []tpm2.TPMSPCRSelection{
		{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(keys...),
		},
	}, tpm2.TPM2BDigest{}, 0)
	defer tpmDeviceB.Close()
	_, err = Unseal(&UnSealConfig{
		TPMConfig: TPMConfig{
			TPMDevice: tpmDeviceB,
		},
		Parent:      H2,
		Key:         b,
		AuthSession: s,
	})
	require.Error(t, err)

}

func TestPasswordFail(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwr := transport.FromReadWriter(tpmDeviceB)

	dataToSeal := "somesecret"
	passphrase := "somepassword"
	badpassphrase := "anotherpassword"
	b, err := Seal(&SealConfig{
		TPMConfig: TPMConfig{
			TPMDevice:   tpmDeviceB,
			KeyPassword: []byte(passphrase),
		},
		Parent: H2,
		Key:    []byte(dataToSeal),
	})
	require.NoError(t, err)
	s, err := NewPolicyPasswordSession(rwr, []byte(badpassphrase), 0)
	require.NoError(t, err)

	defer tpmDeviceB.Close()
	_, err = Unseal(&UnSealConfig{
		TPMConfig: TPMConfig{
			TPMDevice: tpmDeviceB,
		},
		Parent:      H2,
		Key:         b,
		AuthSession: s,
	})
	require.Error(t, err)

}
