// Seal/Unseal data on a Trusted Platform Module (TPM)

package tpmseal

import (
	"bytes"
	"fmt"
	"io"
	"os"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	genkeyutil "github.com/salrashid123/tpm2genkey/util"
)

// Base configuration for seal and unseal functions
type TPMConfig struct {
	TPMPath   string             // path to initialize a TPM; seal/unseal and then close
	TPMDevice io.ReadWriteCloser // initialized transport for the TPM; does not close the readwriter

	Ownerpassword []byte // password for the owner
	KeyPassword   []byte // password for the owner

	SessionEncryptionHandle tpm2.TPMHandle // (optional) handle to use for transit encryption
}

const ()

// configuration  for sealing data
type SealConfig struct {
	TPMConfig
	Name   string
	Key    []byte          // the key to seal
	PcrMap map[uint][]byte // list of pcr:hexvalues to bind to
	Parent ParentType      // the parent key type (recommend h2)
}

type UnSealConfig struct {
	TPMConfig
	Parent      ParentType // the parent key type used during sealing
	Key         []byte     // the bytes of the PEM key to unseal
	AuthSession Session    // a session used for PCR or Password protected keys
}

// Seals data and encodes the result as a PEM formatted TPM key.
func Seal(s *SealConfig) ([]byte, error) {

	if len(s.Key) > MAX_BUFFER {
		return nil, fmt.Errorf("tpmseal can only seal 128bytes of data")
	}

	if s.TPMConfig.TPMDevice == nil && s.TPMConfig.TPMPath == "" {
		return nil, fmt.Errorf("tpmseal can't set both TPMDevice and TPMPath")
	}

	var rwc io.ReadWriteCloser
	if s.TPMConfig.TPMDevice != nil {
		rwc = s.TPMConfig.TPMDevice
	} else {
		var err error
		rwc, err = openTPM(s.TPMConfig.TPMPath)
		if err != nil {
			return nil, fmt.Errorf("tpmseal can't open TPM [%s]", s.TPMConfig.TPMPath)
		}
		defer rwc.Close()
	}
	rwr := transport.FromReadWriter(rwc)

	var encryptionPub *tpm2.TPMTPublic
	// if the user didn't provide  as encryption session
	if s.TPMConfig.SessionEncryptionHandle == 0 {
		// get the endorsement key for the local TPM which we will use for parameter encryption
		createEKRsp, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHEndorsement,
			InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error creating EK Primary  %v", err)
		}
		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: createEKRsp.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()
		// now get the encryption session's name
		encryptionPub, err = createEKRsp.OutPublic.Contents()
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error getting session encryption public contents %v", err)
		}

		s.TPMConfig.SessionEncryptionHandle = createEKRsp.ObjectHandle
	} else {
		var err error
		rpub, err := tpm2.ReadPublic{
			ObjectHandle: s.TPMConfig.SessionEncryptionHandle,
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error getting public encryption public contents %v", err)
		}

		encryptionPub, err = rpub.OutPublic.Contents()
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error getting session encryption public contents %v", err)
		}
	}

	// create a full encryption session for rest of the operations
	rsessInOut := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(s.TPMConfig.SessionEncryptionHandle, *encryptionPub))

	defer func() {
		flushContextInOut := tpm2.FlushContext{
			FlushHandle: rsessInOut.Handle(),
		}
		_, _ = flushContextInOut.Execute(rwr)
	}()

	// get the specified pcrs
	_, pcrList, pcrHash, err := getPCRMap(tpm2.TPMAlgSHA256, s.PcrMap)
	if err != nil {
		return nil, fmt.Errorf("tpmseal:  Could not get PCRMap: %s", err)
	}

	// create the parent
	var parent tpm2.TPMHandle

	var template tpm2.TPMTPublic
	var sessparent tpm2.Session
	var cleanupparent func() error

	switch s.Parent {
	case RSASRK:
		parent = tpm2.TPMRHOwner
		template = tpm2.RSASRKTemplate
		sessparent = tpm2.PasswordAuth([]byte(s.TPMConfig.Ownerpassword))
	case ECCSRK:
		parent = tpm2.TPMRHOwner
		template = tpm2.ECCSRKTemplate
		sessparent = tpm2.PasswordAuth([]byte(s.TPMConfig.Ownerpassword))
	case RSAEK:
		parent = tpm2.TPMRHEndorsement
		template = tpm2.RSAEKTemplate
		sessparent, cleanupparent, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, fmt.Errorf("setting up trial session: %v", err)
		}
		defer cleanupparent()

		_, err = tpm2.PolicySecret{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHEndorsement,
				Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
				Auth:   tpm2.PasswordAuth([]byte(s.TPMConfig.Ownerpassword)),
			},
			PolicySession: sessparent.Handle(),
			NonceTPM:      sessparent.NonceTPM(),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error executing PolicySecret: %v", err)
		}
	case ECCEK:
		parent = tpm2.TPMRHEndorsement
		template = tpm2.ECCEKTemplate
		sessparent = tpm2.PasswordAuth([]byte(s.TPMConfig.Ownerpassword))
		sessparent, cleanupparent, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, fmt.Errorf("setting up trial session: %v", err)
		}
		defer cleanupparent()
		_, err = tpm2.PolicySecret{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHEndorsement,
				Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
				Auth:   tpm2.PasswordAuth([]byte(s.TPMConfig.Ownerpassword)),
			},
			PolicySession: sessparent.Handle(),
			NonceTPM:      sessparent.NonceTPM(),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error executing PolicySecret: %v", err)
		}
	case H2:
		parent = tpm2.TPMRHOwner
		template = keyfile.ECCSRK_H2_Template
		sessparent = tpm2.PasswordAuth([]byte(s.TPMConfig.Ownerpassword))
	default:
		parent = tpm2.TPMRHOwner
		template = tpm2.RSASRKTemplate
		sessparent = tpm2.PasswordAuth([]byte(s.TPMConfig.Ownerpassword))
	}

	var createdParent tpm2.TPMHandle
	var createdParentName tpm2.TPM2BName
	if s.Parent == RSAEK || s.Parent == ECCEK {

		cPrimary, err := tpm2.CreatePrimary{
			PrimaryHandle: parent,
			InPublic:      tpm2.New2B(template),
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: can't create primary %v", err)
		}
		defer func() {
			flush := tpm2.FlushContext{
				FlushHandle: cPrimary.ObjectHandle,
			}
			_, err = flush.Execute(rwr)
		}()

		createdParent = cPrimary.ObjectHandle
		createdParentName = cPrimary.Name
	} else {
		cPrimary, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.AuthHandle{
				Handle: parent,
				Name:   tpm2.HandleName(parent),
				Auth:   sessparent,
			},
			InPublic: tpm2.New2B(template),
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: can't create primary %v", err)
		}
		defer func() {
			flush := tpm2.FlushContext{
				FlushHandle: cPrimary.ObjectHandle,
			}
			_, err = flush.Execute(rwr)
		}()

		createdParent = cPrimary.ObjectHandle
		createdParentName = cPrimary.Name
	}

	// this is an optional list which holds the calculated polcies
	// to encode into the key file PEM
	// note this is not on by default and must be enabled via environment variable. (export ENABLE_POLICY_SYNTAX=1)
	//  critically, its not supportted by openssl
	// see https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-key-policy-specification
	var ap []*keyfile.TPMPolicy

	// now create a session to setup the keys.  For each, operation, pass the encryption session public as the salt
	// this session will setup the pcr digest and password (policy)
	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(s.TPMConfig.SessionEncryptionHandle, *encryptionPub)}...)
	if err != nil {
		return nil, fmt.Errorf("tpmseal: setting up trial session: %v", err)
	}
	defer func() {
		if err := cleanup1(); err != nil {
			//fmt.Printf("tpmseal: cleaning up trial session: %v", err)
		}
	}()

	if len(pcrList) > 0 && len(s.KeyPassword) > 0 {

		sel := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
				},
			},
		}

		// optionally, if we need to encode the policies into the key
		//  the following is usually off by default but we're calculating it here
		//  note that the policy isna't actually even associated with a seeesion...all the following does is
		// caluclates a digest and saves it into the list of policies which is later encoded into the PEM keyfile

		// start policy calculator
		papcr := tpm2.PolicyPCR{
			PcrDigest: tpm2.TPM2BDigest{
				Buffer: pcrHash,
			},
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: sel.PCRSelections,
			},
		}

		pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: eerror setting up NewPolicyCalculator for PolicyAuthValue : %v", err)
		}
		err = papcr.Update(pol)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: eerror updating NewPolicyCalculator for PolicyAuthValue %v", err)
		}
		e, err := genkeyutil.CPBytes(papcr)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: eerror creating cpbytes PolicyAuthValue: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyPCR),
			CommandPolicy: e,
		})
		paa := tpm2.PolicyAuthValue{}
		polav, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error setting up NewPolicyCalculator for PolicyAuthValue : %v", err)
		}
		err = paa.Update(polav)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error updating NewPolicyCalculator for PolicyAuthValue %v", err)
		}
		eav, err := genkeyutil.CPBytes(paa)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error creating cpbytes PolicyAuthValue: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyAuthValue),
			CommandPolicy: eav,
		})

		// end policy calculator

		// now create the real policies bound to sess.Handle()

		_, err = tpm2.PolicyPCR{
			PolicySession: sess.Handle(),
			PcrDigest: tpm2.TPM2BDigest{
				Buffer: pcrHash,
			},
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: sel.PCRSelections,
			},
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error executing PolicyPCR: %v", err)
		}

		_, err = tpm2.PolicyAuthValue{
			PolicySession: sess.Handle(),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: executing PolicyAuthValue: %v", err)
		}
	} else if len(pcrList) > 0 && len(s.KeyPassword) == 0 {

		sel := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
				},
			},
		}

		// policy calculator
		papcr := tpm2.PolicyPCR{
			PcrDigest: tpm2.TPM2BDigest{
				Buffer: pcrHash,
			},
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: sel.PCRSelections,
			},
		}
		pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error setting up NewPolicyCalculator for PolicyAuthValue : %v", err)
		}
		err = papcr.Update(pol)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error updating NewPolicyCalculator for PolicyAuthValue %v", err)
		}
		e, err := genkeyutil.CPBytes(papcr)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error creating cpbytes PolicyAuthValue: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyPCR),
			CommandPolicy: e,
		})
		// end policy calculator

		_, err = tpm2.PolicyPCR{
			PolicySession: sess.Handle(),
			PcrDigest: tpm2.TPM2BDigest{
				Buffer: pcrHash,
			},
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: sel.PCRSelections,
			},
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error executing PolicyPCR: %v", err)
		}
	} else if len(pcrList) == 0 && len(s.KeyPassword) > 0 {

		// start policy calculator
		paa := tpm2.PolicyAuthValue{}
		pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error setting up NewPolicyCalculator for PolicyAuthValue : %v", err)
		}
		err = paa.Update(pol)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error updating NewPolicyCalculator for PolicyAuthValue %v", err)
		}
		e, err := genkeyutil.CPBytes(paa)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error creating cpbytes PolicyAuthValue: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyAuthValue),
			CommandPolicy: e,
		})
		// end policy calculation

		// now run an actually policy against the session
		_, err = tpm2.PolicyAuthValue{
			PolicySession: sess.Handle(),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: executing PolicyAuthValue: %v", err)
		}
	}

	// now that we have the pcr's set, get its digest
	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("tpmseal: error executing PolicyGetDigest: %v", err)
	}

	// now that we have the digest, create the actual TPM based key based on the parent
	// remember the sensitive data **is** encoded into this object itself.
	cCreate, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: createdParent,
			Name:   createdParentName,
			Auth:   sessparent,
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:       tpm2.TPMAlgKeyedHash,
			NameAlg:    tpm2.TPMAlgSHA256,
			AuthPolicy: pgd.PolicyDigest, // set the  auth policy
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: false, // <<<<<<<<<<<<<<<<<<<<<< note, always false
			},
		}),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: s.Key, //  <<<<<<<<<<<<<<<<< seal the key
				}),
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(s.TPMConfig.KeyPassword), // set the key auth password
				},
			},
		},
	}.Execute(rwr, rsessInOut)
	if err != nil {
		return nil, fmt.Errorf("tpmseal: can't create object TPM  %v", err)
	}

	err = cleanup1()
	if err != nil {
		return nil, fmt.Errorf("tpmseal: can't clean session  %v", err)
	}

	// now see if we have an env-var flag to enable the experimental PEM policy encoding
	_, ok := os.LookupEnv(policySyntaxEnv)
	if !ok {
		ap = nil
	}

	// create a keyfile representation (eg, a PEM format for the TPM based sealing key)
	tkf := keyfile.NewTPMKey(
		keyfile.OIDLoadableKey,
		cCreate.OutPublic,
		cCreate.OutPrivate,
		keyfile.WithParent(parent),
		keyfile.WithPolicy(ap),
		keyfile.WithUserAuth([]byte(s.KeyPassword)),
		keyfile.WithDescription(s.Name),
	)

	// get the keyfiles PEM bytes
	kfb := new(bytes.Buffer)
	err = keyfile.Encode(kfb, tkf)
	if err != nil {
		return nil, fmt.Errorf("tpmseal: failed to encode TPMKey: %v", err)
	}

	return kfb.Bytes(), nil
}

// Unseals the PEM formatted TPM key and returns the raw sealed bytes
func Unseal(s *UnSealConfig) ([]byte, error) {

	if s.TPMConfig.TPMDevice == nil && s.TPMConfig.TPMPath == "" {
		return nil, fmt.Errorf("tpmseal can't set both TPMDevice and TPMPath")
	}

	var rwc io.ReadWriteCloser
	if s.TPMConfig.TPMDevice != nil {
		rwc = s.TPMConfig.TPMDevice
	} else {
		var err error
		rwc, err = openTPM(s.TPMConfig.TPMPath)
		if err != nil {
			return nil, fmt.Errorf("tpmseal can't open TPM [%s]", s.TPMConfig.TPMPath)
		}
		defer rwc.Close()
	}
	rwr := transport.FromReadWriter(rwc)

	// get the endorsement key for the local TPM which we will use for parameter encryption
	var encryptionPub *tpm2.TPMTPublic
	// if the user didn't provide  as encryption session
	if s.TPMConfig.SessionEncryptionHandle == 0 {
		// get the endorsement key for the local TPM which we will use for parameter encryption
		createEKRsp, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHEndorsement,
			InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error creating EK Primary  %v", err)
		}
		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: createEKRsp.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()
		// now get the encryption session's name
		encryptionPub, err = createEKRsp.OutPublic.Contents()
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error getting session encryption public contents %v", err)
		}

		s.TPMConfig.SessionEncryptionHandle = createEKRsp.ObjectHandle
	} else {
		var err error
		rpub, err := tpm2.ReadPublic{
			ObjectHandle: s.TPMConfig.SessionEncryptionHandle,
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error getting public encryption public contents %v", err)
		}

		encryptionPub, err = rpub.OutPublic.Contents()
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error getting session encryption public contents %v", err)
		}
	}

	// use the same parameter encryption for the policy sessions
	if s.AuthSession != nil {
		s.AuthSession.SetEncryptionHandler(s.TPMConfig.SessionEncryptionHandle)
	}

	// create a full encryption session for rest of the operations
	rsessInOut := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(s.TPMConfig.SessionEncryptionHandle, *encryptionPub))

	defer func() {
		flushContextInOut := tpm2.FlushContext{
			FlushHandle: rsessInOut.Handle(),
		}
		_, _ = flushContextInOut.Execute(rwr)
	}()

	regenKey, err := keyfile.Decode(s.Key)
	if err != nil {
		return nil, fmt.Errorf("tpmseal: error decrypting regenerated key: %w", err)
	}

	// // create the parent
	var parent tpm2.TPMHandle
	var parentName tpm2.TPM2BName
	var template tpm2.TPMTPublic
	var sessparent tpm2.Session
	var cleanupparent func() error

	if keyfile.IsMSO(tpm2.TPMHandle(regenKey.Parent), keyfile.TPM_HT_PERMANENT) {
		switch regenKey.Parent {
		case tpm2.TPMRHOwner:
			//fmt.Println("parent is owner")
		case tpm2.TPMRHEndorsement:
			//fmt.Println("parent is endorsement")
		default:
			//fmt.Println("parent is transient?")
		}
	} else {
		return nil, fmt.Errorf("tpmseal: transient parent keys not supported yet: %d", regenKey.Parent)
	}

	switch s.Parent {
	case RSASRK:
		parent = tpm2.TPMRHOwner
		template = tpm2.RSASRKTemplate
		sessparent = tpm2.PasswordAuth([]byte(s.TPMConfig.Ownerpassword))
	case ECCSRK:
		parent = tpm2.TPMRHOwner
		template = tpm2.ECCSRKTemplate
		sessparent = tpm2.PasswordAuth([]byte(s.TPMConfig.Ownerpassword))
	case RSAEK:
		parent = tpm2.TPMRHEndorsement
		template = tpm2.RSAEKTemplate
		sessparent, cleanupparent, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, fmt.Errorf("setting up trial session: %v", err)
		}
		defer cleanupparent()

		_, err = tpm2.PolicySecret{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHEndorsement,
				Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
				Auth:   tpm2.PasswordAuth([]byte(s.TPMConfig.Ownerpassword)),
			},
			PolicySession: sessparent.Handle(),
			NonceTPM:      sessparent.NonceTPM(),
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf("error executing PolicySecret: %v", err)
		}
	case ECCEK:
		parent = tpm2.TPMRHEndorsement
		template = tpm2.ECCEKTemplate
		sessparent = tpm2.PasswordAuth([]byte(s.TPMConfig.Ownerpassword))
		sessparent, cleanupparent, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, fmt.Errorf("setting up trial session: %v", err)
		}
		defer cleanupparent()
		_, err = tpm2.PolicySecret{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHEndorsement,
				Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
				Auth:   tpm2.PasswordAuth([]byte(s.TPMConfig.Ownerpassword)),
			},
			PolicySession: sessparent.Handle(),
			NonceTPM:      sessparent.NonceTPM(),
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf("error executing PolicySecret: %v", err)
		}
	case H2:
		parent = tpm2.TPMRHOwner
		template = keyfile.ECCSRK_H2_Template
		sessparent = tpm2.PasswordAuth([]byte(s.TPMConfig.Ownerpassword))
	default:
		parent = tpm2.TPMRHOwner
		template = tpm2.RSASRKTemplate
		sessparent = tpm2.PasswordAuth([]byte(s.TPMConfig.Ownerpassword))
	}

	if s.Parent == RSAEK || s.Parent == ECCEK {

		cPrimary, err := tpm2.CreatePrimary{
			PrimaryHandle: parent,
			InPublic:      tpm2.New2B(template),
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: can't create primary %v", err)
		}
		defer func() {
			flush := tpm2.FlushContext{
				FlushHandle: cPrimary.ObjectHandle,
			}
			_, err = flush.Execute(rwr)
		}()

		parent = cPrimary.ObjectHandle
		parentName = cPrimary.Name
	} else {
		cPrimary, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.AuthHandle{
				Handle: parent,
				Name:   tpm2.HandleName(parent),
				Auth:   sessparent,
			},
			InPublic: tpm2.New2B(template),
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: can't create primary %v", err)
		}
		defer func() {
			flush := tpm2.FlushContext{
				FlushHandle: cPrimary.ObjectHandle,
			}
			_, err = flush.Execute(rwr)
		}()

		parent = cPrimary.ObjectHandle
		parentName = cPrimary.Name
	}

	var aKey *tpm2.LoadResponse
	if s.Parent == RSAEK || s.Parent == ECCEK {
		sessparent, cleanupparent, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, fmt.Errorf("setting up trial session: %v", err)
		}
		defer cleanupparent()

		_, err = tpm2.PolicySecret{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHEndorsement,
				Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
				Auth:   tpm2.PasswordAuth([]byte(s.TPMConfig.Ownerpassword)),
			},
			PolicySession: sessparent.Handle(),
			NonceTPM:      sessparent.NonceTPM(),
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf("error executing PolicySecret: %v", err)
		}

		aKey, err = tpm2.Load{
			ParentHandle: tpm2.AuthHandle{
				Handle: parent,
				Name:   parentName,
				Auth:   sessparent,
			},
			InPrivate: regenKey.Privkey,
			InPublic:  regenKey.Pubkey,
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: can't load object  %v", err)
		}
		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: aKey.ObjectHandle,
			}
			_, err = flushContextCmd.Execute(rwr)
		}()
	} else {
		aKey, err = tpm2.Load{
			ParentHandle: tpm2.NamedHandle{
				Handle: parent,
				Name:   parentName,
			},
			InPrivate: regenKey.Privkey,
			InPublic:  regenKey.Pubkey,
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf("tpmseal: can't load object  %v", err)
		}
		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: aKey.ObjectHandle,
			}
			_, err = flushContextCmd.Execute(rwr)
		}()
	}

	var sess tpm2.Session
	var sesscloser func() error
	if s.AuthSession == nil {
		sess, sesscloser, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptOut), tpm2.Salted(s.TPMConfig.SessionEncryptionHandle, *encryptionPub))
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error crrating policy session for unseal: %v", err)
		}

	} else {
		sess, sesscloser, err = s.AuthSession.GetSession()
		if err != nil {
			return nil, fmt.Errorf("tpmseal: error executing getSession: %v", err)
		}
	}
	defer sesscloser()
	unsealresp, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: aKey.ObjectHandle,
			Name:   aKey.Name,
			Auth:   sess,
		},
	}.Execute(rwr) // since we're using an encrypted session already (sess),  the transmitted data is also encrypted
	if err != nil {
		return nil, fmt.Errorf("tpmseal: error executing unseal: %v", err)
	}
	return unsealresp.OutData.Buffer, nil

}
