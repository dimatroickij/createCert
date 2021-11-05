package ru.voskhod.createSignature.utils;

import CMS_samples.CMStools;
import com.objsys.asn1j.runtime.*;
import ru.CryptoPro.JCP.ASN.CertificateExtensions.GeneralName;
import ru.CryptoPro.JCP.ASN.CertificateExtensions.GeneralNames;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.*;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.*;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.JCP.tools.AlgorithmUtility;

import java.security.*;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;

public class CMSUtils {

    byte[] data;
    String alias;
    String password;
    boolean detached;
    String hash;

    public CMSUtils(byte[] data, String alias, String password, boolean detached) {
        this.data = data;
        this.alias = alias;
        this.password = password;
        this.detached = detached;

    }

    public byte[] createCMS(boolean isContentType, boolean isTime, boolean isSigningCertificateV2) throws Exception {
        KeyStore hdImageStore = KeyStore.getInstance(JCP.HD_STORE_NAME, JCP.PROVIDER_NAME);
        hdImageStore.load(null, null);
        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());
        Certificate cert = hdImageStore.getCertificate(alias);
        String pubKeyAlg = cert.getPublicKey().getAlgorithm();
        String digestOid = AlgorithmUtility.keyAlgToDigestOid(pubKeyAlg);
        ContentInfo all = new ContentInfo();
        SignedData cms = new SignedData();

        all.contentType = new Asn1ObjectIdentifier(new OID(CMStools.STR_CMS_OID_SIGNED).value);
        all.content = cms;
        cms.version = new CMSVersion(1);

        // digest
        cms.digestAlgorithms = new DigestAlgorithmIdentifiers(1);
        DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier(new OID(digestOid).value);

        a.parameters = new Asn1Null();
        cms.digestAlgorithms.elements[0] = a;

        if (detached) {
            cms.encapContentInfo = new EncapsulatedContentInfo(
                    new Asn1ObjectIdentifier(new OID(CMStools.STR_CMS_OID_DATA).value), null);
        } // if
        else {
            cms.encapContentInfo = new EncapsulatedContentInfo(new Asn1ObjectIdentifier(
                    new OID(CMStools.STR_CMS_OID_DATA).value), new Asn1OctetString(data));
        } // else

        // certificate
        cms.certificates = new CertificateSet(1);
        final ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate certificate =
                new ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate();
        final Asn1BerDecodeBuffer decodeBuffer = new Asn1BerDecodeBuffer(cert.getEncoded());
        certificate.decode(decodeBuffer);

        cms.certificates.elements = new CertificateChoices[1];
        cms.certificates.elements[0] = new CertificateChoices();
        cms.certificates.elements[0].set_certificate(certificate);

        final java.security.Signature signature = Signature.getInstance(
                AlgorithmUtility.keyAlgToSignatureOid(privateKey.getAlgorithm()), JCP.PROVIDER_NAME);
        byte[] sign;

        // signer info
        cms.signerInfos = new SignerInfos(1);
        cms.signerInfos.elements[0] = new SignerInfo();
        cms.signerInfos.elements[0].version = new CMSVersion(1);
        cms.signerInfos.elements[0].sid = new SignerIdentifier();

        final byte[] encodedName = ((X509Certificate) cert).getIssuerX500Principal().getEncoded();
        final Asn1BerDecodeBuffer nameBuf = new Asn1BerDecodeBuffer(encodedName);
        final Name name = new Name();
        name.decode(nameBuf);

        CertificateSerialNumber num = new CertificateSerialNumber(((X509Certificate) cert).getSerialNumber());
        cms.signerInfos.elements[0].sid.set_issuerAndSerialNumber(new IssuerAndSerialNumber(name, num));
        cms.signerInfos.elements[0].digestAlgorithm = new DigestAlgorithmIdentifier(new OID(digestOid).value);
        cms.signerInfos.elements[0].digestAlgorithm.parameters = new Asn1Null();
        cms.signerInfos.elements[0].signatureAlgorithm = new SignatureAlgorithmIdentifier(
                new OID(AlgorithmUtility.keyAlgToKeyAlgorithmOid(pubKeyAlg)).value);
        cms.signerInfos.elements[0].signatureAlgorithm.parameters = new Asn1Null();

        final int kmax = 1 + (isContentType ? 1 : 0) + (isTime ? 1 : 0) + (isSigningCertificateV2 ? 1 : 0);
        cms.signerInfos.elements[0].signedAttrs = new SignedAttributes(kmax);
        int k = 0;

        //-message digest
        cms.signerInfos.elements[0].signedAttrs.elements[k] =
                new Attribute(new OID(CMStools.STR_CMS_OID_DIGEST_ATTR).value, new Attribute_values(1));

        final byte[] messageDigestBlob;
        if (cms.encapContentInfo.eContent != null) {
            messageDigestBlob = CMStools.digestm(cms.encapContentInfo.eContent.value, digestOid, JCP.PROVIDER_NAME);
        } // if
        else if (data != null) {
            messageDigestBlob = CMStools.digestm(data, digestOid, JCP.PROVIDER_NAME);
        } // else
        else {
            throw new Exception("No content");
        } // else

        final Asn1Type messageDigest = new Asn1OctetString(messageDigestBlob);

        hash = messageDigest.toString();

        cms.signerInfos.elements[0].signedAttrs.elements[k].values.elements[0] = messageDigest;

        //-contentType
        if (isContentType) {
            k += 1;
            cms.signerInfos.elements[0].signedAttrs.elements[k] = new Attribute(new OID(CMStools.STR_CMS_OID_CONT_TYP_ATTR).value,
                    new Attribute_values(1));
            final Asn1Type conttype = new Asn1ObjectIdentifier(new OID(CMStools.STR_CMS_OID_DATA).value);
            cms.signerInfos.elements[0].signedAttrs.elements[k].values.elements[0] = conttype;
        }

        //-Time
        if (isTime) {
            k += 1;
            cms.signerInfos.elements[0].signedAttrs.elements[k] =
                    new Attribute(new OID(CMStools.STR_CMS_OID_SIGN_TYM_ATTR).value, new Attribute_values(1));
            final Time time = new Time();
            final Asn1UTCTime UTCTime = new Asn1UTCTime();
            //текущая дата с календаря
            UTCTime.setTime(Calendar.getInstance());
            time.set_utcTime(UTCTime);
            cms.signerInfos.elements[0].signedAttrs.elements[k].values.elements[0] = time.getElement();
        }

        // Добавление signingCertificateV2 в подписанные аттрибуты, чтобы подпись
        if (isSigningCertificateV2) {
            k += 1;
            cms.signerInfos.elements[0].signedAttrs.elements[k] =
                    new Attribute(new OID(ALL_PKIX1Explicit88Values.id_aa_signingCertificateV2).value,
                            new Attribute_values(1));
            // Идентификатор алгоритма хеширования, который использовался для
            // хеширования контекста сертификата ключа подписи.
            final DigestAlgorithmIdentifier digestAlgorithmIdentifier =
                    new DigestAlgorithmIdentifier(new OID(digestOid).value);

            // Хеш сертификата ключа подписи.
            final CertHash certHash = new CertHash(CMStools.digestm(cert.getEncoded(), digestOid, JCP.PROVIDER_NAME));

            // Issuer name из сертификата ключа подписи.
            GeneralName generalName = new GeneralName();
            generalName.set_directoryName(name);

            GeneralNames generalNames = new GeneralNames();
            generalNames.elements = new GeneralName[1];
            generalNames.elements[0] = generalName;

            // Комбинируем издателя и серийный номер.
            IssuerSerial issuerSerial = new IssuerSerial(generalNames, num);

            ESSCertIDv2 essCertIDv2 = new ESSCertIDv2(digestAlgorithmIdentifier, certHash, issuerSerial);

            _SeqOfESSCertIDv2 essCertIDv2s = new _SeqOfESSCertIDv2(1);
            essCertIDv2s.elements = new ESSCertIDv2[1];
            essCertIDv2s.elements[0] = essCertIDv2;

            // Добавляем сам аттрибут.
            SigningCertificateV2 signingCertificateV2 = new SigningCertificateV2(essCertIDv2s);
            cms.signerInfos.elements[0].signedAttrs.elements[k].values.elements[0] = signingCertificateV2;
        }

        //signature
        Asn1BerEncodeBuffer encBufSignedAttr = new Asn1BerEncodeBuffer();
        cms.signerInfos.elements[0].signedAttrs.encode(encBufSignedAttr);
        final byte[] hsign = encBufSignedAttr.getMsgCopy();
        signature.initSign(privateKey);
        signature.update(hsign);
        sign = signature.sign();

        cms.signerInfos.elements[0].signature = new SignatureValue(sign);

        // encode
        final Asn1BerEncodeBuffer asnBuf = new Asn1BerEncodeBuffer();
        all.encode(asnBuf, true);
        return asnBuf.getMsgCopy();
    }

    public String getHash() {
        return hash;
    }
}
