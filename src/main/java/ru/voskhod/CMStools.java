/**
 * $RCSfile$
 * version $Revision: 38343 $
 * created 21.04.2009 16:51:19 by kunina
 * last modified $Date: 2015-07-04 12:21:40 +0300 (Сб., 04 июля 2015) $ by $Author: afevma $
 * (C) ООО Крипто-Про 2004-2009.
 *
 * Программный код, содержащийся в этом файле, предназначен
 * для целей обучения. Может быть скопирован или модифицирован 
 * при условии сохранения абзацев с указанием авторства и прав.
 *
 * Данный код не может быть непосредственно использован
 * для защиты информации. Компания Крипто-Про не несет никакой
 * ответственности за функционирование этого кода.
 */
package ru.voskhod;

import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.tools.Array;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.logging.Logger;

/**
 * @author Copyright 2004-2009 Crypto-Pro. All rights reserved.
 * @.Version
 */
public class CMStools {

/**
 * расширение файла сертификата
 */
public static final String CERT_EXT = ".cer";
/**
 * расширение файла
 */
public static final String CMS_EXT = ".p7b";
/**
 * разделитель
 */
public static final String SEPAR = File.separator;


/**
 * алгоритмы и т.д.
 */

public static final String STORE_TYPE = JCP.HD_STORE_NAME;

// ГОСТ Р 34.10-2001
public static final String KEY_ALG_NAME = JCP.GOST_EL_DH_NAME;
public static final String DIGEST_ALG_NAME = JCP.GOST_DIGEST_NAME;

// ГОСТ Р 34.10-2012 (256)
public static final String KEY_ALG_NAME_2012_256 = JCP.GOST_DH_2012_256_NAME;
public static final String DIGEST_ALG_NAME_2012_256 = JCP.GOST_DIGEST_2012_256_NAME;

// ГОСТ Р 34.10-2012 (512)
public static final String KEY_ALG_NAME_2012_512 = JCP.GOST_DH_2012_512_NAME;
public static final String DIGEST_ALG_NAME_2012_512 = JCP.GOST_DIGEST_2012_512_NAME;

public static final String SEC_KEY_ALG_NAME = "GOST28147";

/**
 * OIDs для CMS
 */
public static final String STR_CMS_OID_DATA = "1.2.840.113549.1.7.1";
public static final String STR_CMS_OID_SIGNED = "1.2.840.113549.1.7.2";
public static final String STR_CMS_OID_ENVELOPED = "1.2.840.113549.1.7.3";

public static final String STR_CMS_OID_CONT_TYP_ATTR = "1.2.840.113549.1.9.3";
public static final String STR_CMS_OID_DIGEST_ATTR = "1.2.840.113549.1.9.4";
public static final String STR_CMS_OID_SIGN_TYM_ATTR = "1.2.840.113549.1.9.5";

public static final String STR_CMS_OID_TS = "1.2.840.113549.1.9.16.1.4";

// ГОСТ Р 34.10-2001
public static final String DIGEST_OID = JCP.GOST_DIGEST_OID;
public static final String SIGN_OID = JCP.GOST_EL_KEY_OID;

// ГОСТ Р 34.10-2012 (256)
public static final String DIGEST_OID_2012_256 = JCP.GOST_DIGEST_2012_256_OID;
public static final String SIGN_OID_2012_256 = JCP.GOST_PARAMS_SIG_2012_256_KEY_OID;

// ГОСТ Р 34.10-2012 (512)
public static final String DIGEST_OID_2012_512 = JCP.GOST_DIGEST_2012_512_OID;
public static final String SIGN_OID_2012_512 = JCP.GOST_PARAMS_SIG_2012_512_KEY_OID;


/**
 * logger
 */
public static Logger logger = Logger.getLogger("LOG");

private static CertificateFactory cf = null;
private static Certificate rootCert = null;




/**
 * @param name имя
 * @param pathh путь для сохранения
 * @throws KeyStoreException /
 * @throws NoSuchAlgorithmException /
 * @throws IOException /
 * @throws CertificateException /
 */
private static void expCert(String name, String pathh) throws KeyStoreException,
        NoSuchAlgorithmException, IOException, CertificateException {
    final KeyStore ks = KeyStore.getInstance(STORE_TYPE);
    ks.load(null, null);
    final Certificate cert = ks.getCertificate(name);
    Array.writeFile(pathh, cert.getEncoded());
}



/**
 * Получение PrivateKey из store.
 *
 * @param name alias ключа
 * @param password пароль на ключ
 * @return PrivateKey
 * @throws Exception in key read
 */
public static PrivateKey loadKey(String name, char[] password)
        throws Exception {
    final KeyStore hdImageStore = KeyStore.getInstance(CMStools.STORE_TYPE);
    hdImageStore.load(null, null);
    return (PrivateKey) hdImageStore.getKey(name, password);
}

/**
 * Получение certificate из store.
 *
 * @param name alias сертификата.
 * @return Certificate
 * @throws Exception in cert read
 */
public static Certificate loadCertificate(String name)
        throws Exception {
    final KeyStore hdImageStore = KeyStore.getInstance(CMStools.STORE_TYPE);
    hdImageStore.load(null, null);
    return hdImageStore.getCertificate(name);
}

/**
 * read certificate from file.
 *
 * @param fileName certificate file name
 * @return certificate
 * @throws IOException in cert read
 * @throws CertificateException if error file format
 */
public static Certificate readCertificate(String fileName) throws IOException,
        CertificateException {
    FileInputStream fis = null;
    BufferedInputStream bis = null;
    final Certificate cert;
    try {
        fis = new FileInputStream(fileName);
        bis = new BufferedInputStream(fis);
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        cert = cf.generateCertificate(bis);
        return cert;
    } finally {
        if (bis != null) bis.close();
        if (fis != null) fis.close();
    }
}

/**
 * @param bytes bytes
 * @param digestAlgorithmName algorithm
 * @return digest
 * @throws Exception e
 */
public static byte[] digestm(byte[] bytes, String digestAlgorithmName)
        throws Exception {
    return digestm(bytes, digestAlgorithmName, JCP.PROVIDER_NAME);
}

/**
 * @param bytes bytes
 * @param digestAlgorithmName algorithm
 * @param providerName provider name
 * @return digest
 * @throws Exception e
 */
public static byte[] digestm(byte[] bytes, String digestAlgorithmName,
     String providerName) throws Exception {

    //calculation messageDigest
    final ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
    final MessageDigest digest = MessageDigest.getInstance(digestAlgorithmName, providerName);
    final DigestInputStream digestStream = new DigestInputStream(stream, digest);

    while (digestStream.available() != 0) digestStream.read();

    return digest.digest();
}
}
