package tpmseal

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"net"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}

var ()

const (
	MAX_BUFFER      = 128                    // maximum bytes to seal/unseal
	policySyntaxEnv = "ENABLE_POLICY_SYNTAX" // environment variable to toggle if the policy syntax should be applied to the keyfile
)

type ParentType int

// Declare the constants using iota
const (
	RSASRK ParentType = iota // 0
	ECCSRK                   // 1
	RSAEK                    // 2
	ECCEK                    // 3
	H2                       // 4
)

func getPCRMap(algo tpm2.TPMAlgID, pcrMap map[uint][]byte) (map[uint][]byte, []uint, []byte, error) {

	var hsh hash.Hash
	// https://github.com/tpm2-software/tpm2-tools/blob/83f6f8ac5de5a989d447d8791525eb6b6472e6ac/lib/tpm2_openssl.c#L206
	if algo == tpm2.TPMAlgSHA1 {
		hsh = sha1.New()
	}
	if algo == tpm2.TPMAlgSHA256 {
		hsh = sha256.New()
	}

	if algo == tpm2.TPMAlgSHA1 || algo == tpm2.TPMAlgSHA256 {
		for uv, v := range pcrMap {
			pcrMap[uint(uv)] = v
			hsh.Write(v)
		}
	} else {
		return nil, nil, nil, fmt.Errorf("unknown Hash Algorithm for TPM PCRs %v", algo)
	}

	pcrs := make([]uint, 0, len(pcrMap))
	for k := range pcrMap {
		pcrs = append(pcrs, k)
	}

	return pcrMap, pcrs, hsh.Sum(nil), nil
}

type Session interface {
	GetSession() (auth tpm2.Session, closer func() error, err error) // this supplies the session handle to the library
	SetEncryptionHandler(encryptionHandle tpm2.TPMHandle)
}

// for pcr sessions
type PCRSession struct {
	rwr              transport.TPM
	sel              []tpm2.TPMSPCRSelection
	digest           tpm2.TPM2BDigest
	encryptionHandle tpm2.TPMHandle
}

var _ Session = (*PCRSession)(nil)

// Sets up a PCR session.  THe digest parameter signals what PCR digest to expect explicitly.
// Normally, just setting the pcr bank numbers (i.e tpm2.TPMSPCRSelection) will enforce pcr compliance
//
//	useing the original PCR values the key was bound to
//
// If you specify the pcrselection and digest, the digest value you specify is checked explictly vs implictly.
//
//	The digest value lets you 'see' the digest the key is bound to upfront.
//	if the digest is incorrect, you'll see
//	  "tpmjwt: error getting session TPM_RC_VALUE (parameter 1): value is out of range or is not correct for the context"
func NewPCRSession(rwr transport.TPM, sel []tpm2.TPMSPCRSelection, digest tpm2.TPM2BDigest, encryptionHandle tpm2.TPMHandle) (PCRSession, error) {
	return PCRSession{rwr, sel, digest, encryptionHandle}, nil
}

func (p PCRSession) SetEncryptionHandler(encryptionHandle tpm2.TPMHandle) {
	p.encryptionHandle = encryptionHandle
}

func (p PCRSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	var ePubName *tpm2.TPMTPublic
	if p.encryptionHandle != 0 {
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: p.encryptionHandle,
		}.Execute(p.rwr)
		if err != nil {
			return nil, nil, err
		}
		ePubName, err = encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, nil, err
		}
	}

	var pcr_sess tpm2.Session
	var pcr_cleanup func() error

	if p.encryptionHandle != 0 {
		pcr_sess, pcr_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptOut), tpm2.Salted(p.encryptionHandle, *ePubName))
		if err != nil {
			return nil, nil, err
		}
	} else {
		pcr_sess, pcr_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: pcr_sess.Handle(),
		PcrDigest:     p.digest,
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, pcr_cleanup, err
	}

	return pcr_sess, pcr_cleanup, nil
}

// for password sessions
type PasswordAuthSession struct {
	rwr              transport.TPM
	password         []byte
	encryptionHandle tpm2.TPMHandle
}

var _ Session = (*PasswordAuthSession)(nil)

func NewPasswordAuthSession(rwr transport.TPM, password []byte, encryptionHandle tpm2.TPMHandle) (PasswordAuthSession, error) {
	return PasswordAuthSession{rwr, password, encryptionHandle}, nil
}

func (p PasswordAuthSession) SetEncryptionHandler(encryptionHandle tpm2.TPMHandle) {
	p.encryptionHandle = encryptionHandle
}

func (p PasswordAuthSession) GetSession() (auth tpm2.Session, closer func() error, err error) {
	c := func() error { return nil }
	return tpm2.PasswordAuth(p.password), c, nil
}

// for password sessions
type PolicyPasswordSession struct {
	rwr              transport.TPM
	password         []byte
	encryptionHandle tpm2.TPMHandle
}

var _ Session = (*PolicyPasswordSession)(nil)

func NewPolicyPasswordSession(rwr transport.TPM, password []byte, encryptionHandle tpm2.TPMHandle) (PolicyPasswordSession, error) {
	return PolicyPasswordSession{rwr, password, encryptionHandle}, nil
}

func (p PolicyPasswordSession) SetEncryptionHandler(encryptionHandle tpm2.TPMHandle) {
	p.encryptionHandle = encryptionHandle
}

func (p PolicyPasswordSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	var ePubName *tpm2.TPMTPublic
	if p.encryptionHandle != 0 {
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: p.encryptionHandle,
		}.Execute(p.rwr)
		if err != nil {
			return nil, nil, err
		}
		ePubName, err = encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, nil, err
		}
	}

	var policy_auth_value_sess tpm2.Session
	var policy_authvalue_cleanup func() error

	if p.encryptionHandle != 0 {
		policy_auth_value_sess, policy_authvalue_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, tpm2.Auth(p.password), tpm2.AESEncryption(128, tpm2.EncryptOut), tpm2.Salted(p.encryptionHandle, *ePubName))
		if err != nil {
			return nil, nil, err
		}
	} else {
		policy_auth_value_sess, policy_authvalue_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, tpm2.Auth(p.password))
		if err != nil {
			return nil, nil, err
		}
	}

	// sess, c, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(p.password))}...)
	// if err != nil {
	// 	return nil, nil, err
	// }

	_, err = tpm2.PolicyAuthValue{
		PolicySession: policy_auth_value_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, policy_authvalue_cleanup, err
	}

	return policy_auth_value_sess, policy_authvalue_cleanup, nil
}
