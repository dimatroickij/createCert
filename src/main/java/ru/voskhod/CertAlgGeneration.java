package ru.voskhod;

import ru.CryptoPro.JCP.JCP;

import java.security.cert.Certificate;

public class CertAlgGeneration {

    public String PROVIDER_NAME;
    public String DIGEST_OID;
    public String PARAMS_SIG_KEY_OID;
    public String SIGN_NAME;

    public CertAlgGeneration(String sigAlgOID) {
        setFields(sigAlgOID);
    }

    public CertAlgGeneration(Certificate certificate) {
        setFields(certificate.getPublicKey().getAlgorithm());
    }


    private void setFields(String sigAlg) {
        switch (sigAlg) {
            case "1.2.643.2.2.3":
            case "GOST3410EL":
                PROVIDER_NAME = JCP.PROVIDER_NAME;
                DIGEST_OID = JCP.GOST_DIGEST_OID;
//                PARAMS_SIG_KEY_OID = JCP.GOST_EL_KEY_OID;
                PARAMS_SIG_KEY_OID = JCP.GOST_EL_SIGN_2012_256_OID_WITH;
                SIGN_NAME = JCP.GOST_EL_SIGN_NAME;//fixme проверить
                break;
            case "1.2.643.7.1.1.3.2":
            case "GOST3410_2012_256":
                PROVIDER_NAME = JCP.PROVIDER_NAME;
                DIGEST_OID = JCP.GOST_DIGEST_2012_256_OID;
                PARAMS_SIG_KEY_OID = JCP.GOST_PARAMS_SIG_2012_256_KEY_OID;
                SIGN_NAME= JCP.GOST_SIGN_2012_256_NAME;
                break;
            case "1.2.643.7.1.1.3.3":
            case "GOST3410_2012_512":
                PROVIDER_NAME = JCP.PROVIDER_NAME;
                DIGEST_OID = JCP.GOST_DIGEST_2012_512_OID;
                PARAMS_SIG_KEY_OID = JCP.GOST_PARAMS_SIG_2012_512_KEY_OID;
                SIGN_NAME= JCP.GOST_SIGN_2012_512_NAME;
                break;
        }
    }
}
