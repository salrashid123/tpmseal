from tpm2_pytss import *
from tpm2_pytss.internal.templates import _ek
# from tpm2_pytss.internal.templates import ek_rsa2048

import json

from tpm2_pytss.tsskey import TSSPrivKey

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from tpm2_pytss.encoding import (
    base_encdec,
    json_encdec,
)


passphrase = 'foooo'

ectx = ESAPI(tcti="swtpm:port=2321")
ectx.startup(TPM2_SU.CLEAR)


_parent_ecc_template = TPMT_PUBLIC(
    type=TPM2_ALG.ECC,
    nameAlg=TPM2_ALG.SHA256,
    objectAttributes=TPMA_OBJECT.USERWITHAUTH
    | TPMA_OBJECT.RESTRICTED
    | TPMA_OBJECT.DECRYPT
    | TPMA_OBJECT.NODA
    | TPMA_OBJECT.FIXEDTPM
    | TPMA_OBJECT.FIXEDPARENT
    | TPMA_OBJECT.SENSITIVEDATAORIGIN,
    authPolicy=b"",
    parameters=TPMU_PUBLIC_PARMS(
        eccDetail=TPMS_ECC_PARMS(
            symmetric=TPMT_SYM_DEF_OBJECT(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
            scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
            curveID=TPM2_ECC.NIST_P256,
            kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
        ),
    ),
)
inSensitive = TPM2B_SENSITIVE_CREATE()
primary1, _, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))


f = open("/tmp/private.pem", "r")
k = TSSPrivKey.from_pem(f.read().encode("utf-8"))

aesKeyHandle = ectx.load(primary1, k.private, k.public)
ectx.flush_context(primary1)


sess = ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=TPMT_SYM_DEF(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(sym=128),
                mode=TPMU_SYM_MODE(sym=TPM2_ALG.CFB),
            ),        
            auth_hash=TPM2_ALG.SHA256,
        )


pol={
    "description":"Policy authvalue",
    "policy":[
                        {
                            "type": "authValue",
                        }
    ]
}

polstr = json.dumps(pol).encode()
try:
    with policy(polstr, TPM2_ALG.SHA256) as p:
                p.calculate()
                cjb = p.get_calculated_json()
                json_object = json.loads(cjb)
                # print(json.dumps(json_object, indent=4))
                p.execute(ectx, sess)
except Exception as e:
    print(e)
    sys.exit(1)


ectx.tr_set_auth(aesKeyHandle, passphrase)
encrypted = ectx.unseal(aesKeyHandle, session1=sess)
print(encrypted.buffer.tobytes().decode('utf-8'))

ectx.flush_context(sess)
ectx.flush_context(aesKeyHandle)
ectx.close()