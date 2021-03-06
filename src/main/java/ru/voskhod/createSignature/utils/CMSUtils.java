package ru.voskhod.createSignature.utils;


import com.objsys.asn1j.runtime.*;
import org.bouncycastle.util.encoders.Base64;
import ru.CryptoPro.JCP.ASN.CertificateExtensions.GeneralName;
import ru.CryptoPro.JCP.ASN.CertificateExtensions.GeneralNames;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.*;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.*;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.JCP.tools.AlgorithmUtility;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;

public class CMSUtils {

    byte[] data;
    byte[] signature;
    boolean detached;
    String hash;
    byte[] digest;

    public static final String STR_CMS_OID_SIGNED = "1.2.840.113549.1.7.2";
    public static final String STR_CMS_OID_DATA = "1.2.840.113549.1.7.1";
    public static final String STR_CMS_OID_DIGEST_ATTR = "1.2.840.113549.1.9.4";
    public static final String STR_CMS_OID_CONT_TYP_ATTR = "1.2.840.113549.1.9.3";
    public static final String STR_CMS_OID_SIGN_TYM_ATTR = "1.2.840.113549.1.9.5";

    public static String VerifyCMSSignature = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyCMSSignature>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyCMSSignature>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    public static String VerifyCMSSignatureWithReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyCMSSignatureWithReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyCMSSignatureWithReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    public static String VerifyCMSSignatureWithSignedReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyCMSSignatureWithSignedReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyCMSSignatureWithSignedReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    String VerifyCMSSignatureByHash = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyCMSSignatureByHash>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:hash>{%hash%}</esv:hash>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyCMSSignatureByHash>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    String VerifyCMSSignatureByHashWithReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyCMSSignatureByHashWithReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:hash>{%hash%}</esv:hash>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyCMSSignatureByHashWithReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    String VerifyCMSSignatureByHashWithSignedReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyCMSSignatureByHashWithSignedReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:hash>{%hash%}</esv:hash>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyCMSSignatureByHashWithSignedReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    String VerifyCMSSignatureDetached = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyCMSSignatureDetached>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:originalContent>{%originalContent%}</esv:originalContent>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyCMSSignatureDetached>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    String VerifyCMSSignatureDetachedWithReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyCMSSignatureDetachedWithReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:originalContent>{%originalContent%}</esv:originalContent>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyCMSSignatureDetachedWithReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    String VerifyCMSSignatureDetachedWithSignedReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyCMSSignatureDetachedWithSignedReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:originalContent>{%originalContent%}</esv:originalContent>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyCMSSignatureDetachedWithSignedReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    public CMSUtils(byte[] data, String alias, String password, boolean detached, boolean isContentType, boolean isTime,
                    boolean isSigningCertificateV2) throws Exception {
        this.data = data;
        this.detached = detached;
        createCMS(alias, password, isContentType, isTime, isSigningCertificateV2);
    }

    public CMSUtils(byte[] signature) throws Exception {
        this.signature = signature;
        this.detached = false;

        ContentInfo all = new ContentInfo();
        Asn1BerDecodeBuffer asn1Buf = new Asn1BerDecodeBuffer(signature);
        all.decode(asn1Buf);
        SignedData cms = (SignedData) all.content;

        this.data = cms.encapContentInfo.eContent.value;

        Asn1BerEncodeBuffer encodeBuffer = new Asn1BerEncodeBuffer();
        cms.certificates.elements[0].encode(encodeBuffer);

        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        final X509Certificate cert = (X509Certificate) cf
                .generateCertificate(encodeBuffer.getInputStream());

        String digestOid = AlgorithmUtility.keyAlgToDigestOid(cert.getPublicKey().getAlgorithm());

        this.digest = digestm(this.data, digestOid, JCP.PROVIDER_NAME);
        this.hash = new Asn1OctetString(this.digest).toString();
    }

    public static byte[] digestm(byte[] var0, String var1, String var2) throws Exception {
        ByteArrayInputStream var3 = new ByteArrayInputStream(var0);
        MessageDigest var4 = var2 != null ? MessageDigest.getInstance(var1, var2) : MessageDigest.getInstance(var1);
        DigestInputStream var5 = new DigestInputStream(var3, var4);

        while(var5.available() != 0) {
            var5.read();
        }

        return var4.digest();
    }

    public CMSUtils(byte[] signature, byte[] data) throws Exception {
        this.signature = signature;
        this.detached = true;
        this.data = data;

        ContentInfo all = new ContentInfo();
        Asn1BerDecodeBuffer asn1Buf = new Asn1BerDecodeBuffer(signature);
        all.decode(asn1Buf);

        SignedData cms = (SignedData) all.content;

        Asn1BerEncodeBuffer encodeBuffer = new Asn1BerEncodeBuffer();
        cms.certificates.elements[0].encode(encodeBuffer);

        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        final X509Certificate cert = (X509Certificate) cf
                .generateCertificate(encodeBuffer.getInputStream());

        String digestOid = AlgorithmUtility.keyAlgToDigestOid(cert.getPublicKey().getAlgorithm());

        this.digest = digestm(this.data, digestOid, JCP.PROVIDER_NAME);
        this.hash = new Asn1OctetString(this.digest).toString();
    }

    private void createCMS(String alias, String password, boolean isContentType, boolean isTime,
                           boolean isSigningCertificateV2) throws Exception {
        KeyStore hdImageStore = KeyStore.getInstance(JCP.HD_STORE_NAME, JCP.PROVIDER_NAME);
        hdImageStore.load(null, null);
        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());
        Certificate cert = hdImageStore.getCertificate(alias);
        String pubKeyAlg = cert.getPublicKey().getAlgorithm();
        String digestOid = AlgorithmUtility.keyAlgToDigestOid(pubKeyAlg);
        ContentInfo all = new ContentInfo();
        SignedData cms = new SignedData();

        all.contentType = new Asn1ObjectIdentifier(new OID(STR_CMS_OID_SIGNED).value);
        all.content = cms;
        cms.version = new CMSVersion(1);

        // digest
        cms.digestAlgorithms = new DigestAlgorithmIdentifiers(1);
        DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier(new OID(digestOid).value);

        a.parameters = new Asn1Null();
        cms.digestAlgorithms.elements[0] = a;

        if (detached) {
            cms.encapContentInfo = new EncapsulatedContentInfo(
                    new Asn1ObjectIdentifier(new OID(STR_CMS_OID_DATA).value), null);
        } // if
        else {
            cms.encapContentInfo = new EncapsulatedContentInfo(new Asn1ObjectIdentifier(
                    new OID(STR_CMS_OID_DATA).value), new Asn1OctetString(data));
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
                new Attribute(new OID(STR_CMS_OID_DIGEST_ATTR).value, new Attribute_values(1));

        if (cms.encapContentInfo.eContent != null) {
            digest = digestm(cms.encapContentInfo.eContent.value, digestOid, JCP.PROVIDER_NAME);
        } // if
        else if (data != null) {
            digest = digestm(data, digestOid, JCP.PROVIDER_NAME);
        } // else
        else {
            throw new Exception("No content");
        } // else
        final Asn1Type messageDigest = new Asn1OctetString(digest);
        hash = messageDigest.toString();

        cms.signerInfos.elements[0].signedAttrs.elements[k].values.elements[0] = messageDigest;

        //-contentType
        if (isContentType) {
            k += 1;
            cms.signerInfos.elements[0].signedAttrs.elements[k] = new Attribute(
                    new OID(STR_CMS_OID_CONT_TYP_ATTR).value, new Attribute_values(1));
            final Asn1Type conttype = new Asn1ObjectIdentifier(new OID(STR_CMS_OID_DATA).value);
            cms.signerInfos.elements[0].signedAttrs.elements[k].values.elements[0] = conttype;
        }

        //-Time
        if (isTime) {
            k += 1;
            cms.signerInfos.elements[0].signedAttrs.elements[k] =
                    new Attribute(new OID(STR_CMS_OID_SIGN_TYM_ATTR).value, new Attribute_values(1));
            final Time time = new Time();
            final Asn1UTCTime UTCTime = new Asn1UTCTime();
            //?????????????? ???????? ?? ??????????????????
            UTCTime.setTime(Calendar.getInstance());
            time.set_utcTime(UTCTime);
            cms.signerInfos.elements[0].signedAttrs.elements[k].values.elements[0] = time.getElement();
        }

        // ???????????????????? signingCertificateV2 ?? ?????????????????????? ??????????????????, ?????????? ??????????????
        if (isSigningCertificateV2) {
            k += 1;
            cms.signerInfos.elements[0].signedAttrs.elements[k] =
                    new Attribute(new OID(ALL_PKIX1Explicit88Values.id_aa_signingCertificateV2).value,
                            new Attribute_values(1));
            // ?????????????????????????? ?????????????????? ??????????????????????, ?????????????? ?????????????????????????? ??????
            // ?????????????????????? ?????????????????? ?????????????????????? ?????????? ??????????????.
            final DigestAlgorithmIdentifier digestAlgorithmIdentifier =
                    new DigestAlgorithmIdentifier(new OID(digestOid).value);

            // ?????? ?????????????????????? ?????????? ??????????????.
            final CertHash certHash = new CertHash(digestm(cert.getEncoded(), digestOid, JCP.PROVIDER_NAME));

            // Issuer name ???? ?????????????????????? ?????????? ??????????????.
            GeneralName generalName = new GeneralName();
            generalName.set_directoryName(name);

            GeneralNames generalNames = new GeneralNames();
            generalNames.elements = new GeneralName[1];
            generalNames.elements[0] = generalName;

            // ?????????????????????? ???????????????? ?? ???????????????? ??????????.
            IssuerSerial issuerSerial = new IssuerSerial(generalNames, num);

            ESSCertIDv2 essCertIDv2 = new ESSCertIDv2(digestAlgorithmIdentifier, certHash, issuerSerial);

            _SeqOfESSCertIDv2 essCertIDv2s = new _SeqOfESSCertIDv2(1);
            essCertIDv2s.elements = new ESSCertIDv2[1];
            essCertIDv2s.elements[0] = essCertIDv2;

            // ?????????????????? ?????? ????????????????.
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
        this.signature = asnBuf.getMsgCopy();
    }

    public byte[] getSignature() {
        return this.signature;
    }

    public String getHash() {
        return this.hash;
    }

    public byte[] getDigest() {
        return this.digest;
    }

    public byte[] createVerifyCMS(boolean verifySignatureOnly) {
        return VerifyCMSSignature.replace("{%message%}", Base64.toBase64String(this.signature))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }

    public byte[] createVerifyCMSWithReport(boolean verifySignatureOnly) {
        return VerifyCMSSignatureWithReport.replace("{%message%}", Base64.toBase64String(this.signature))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }

    public byte[] createVerifyCMSWithSignedReport(boolean verifySignatureOnly) {
        return VerifyCMSSignatureWithSignedReport.replace("{%message%}", Base64.toBase64String(this.signature))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }

    public byte[] createVerifyCMSByHash(boolean verifySignatureOnly) {
        return VerifyCMSSignatureByHash.replace("{%message%}", Base64.toBase64String(this.signature))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .replace("{%hash%}", Base64.toBase64String(this.digest)).getBytes(StandardCharsets.UTF_8);
    }

    public byte[] createVerifyCMSByHashWithReport(boolean verifySignatureOnly) {
        return VerifyCMSSignatureByHashWithReport.replace("{%message%}", Base64.toBase64String(this.signature))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .replace("{%hash%}", Base64.toBase64String(this.digest)).getBytes(StandardCharsets.UTF_8);
    }

    public byte[] createVerifyCMSByHashWithSignedReport(boolean verifySignatureOnly) {
        return VerifyCMSSignatureByHashWithSignedReport.replace("{%message%}", Base64.toBase64String(signature))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .replace("{%hash%}", Base64.toBase64String(this.digest)).getBytes(StandardCharsets.UTF_8);
    }

    public byte[] createVerifyCMSDetached(boolean verifySignatureOnly) {
        return VerifyCMSSignatureDetached.replace("{%message%}", Base64.toBase64String(this.signature))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .replace("{%originalContent%}", Base64.toBase64String(data)).getBytes(StandardCharsets.UTF_8);
    }

    public byte[] createVerifyCMSDetachedWithReport(boolean verifySignatureOnly) {
        return VerifyCMSSignatureDetachedWithReport.replace("{%message%}", Base64.toBase64String(signature))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .replace("{%originalContent%}", Base64.toBase64String(data)).getBytes(StandardCharsets.UTF_8);
    }

    public byte[] createVerifyCMSDetachedWithSignedReport(boolean verifySignatureOnly) {
        return VerifyCMSSignatureDetachedWithSignedReport.replace("{%message%}",
                Base64.toBase64String(this.signature)).replace("{%verifySignatureOnly%}",
                String.valueOf(verifySignatureOnly)).replace("{%originalContent%}",
                Base64.toBase64String(this.data)).getBytes(StandardCharsets.UTF_8);
    }
}
