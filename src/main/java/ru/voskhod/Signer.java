package ru.voskhod;

import com.objsys.asn1j.runtime.*;
import com.sun.org.apache.xml.internal.security.Init;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.*;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.CertificateSerialNumber;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Name;
import ru.CryptoPro.JCP.Digest.GostDigest;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.JCP.tools.AlgorithmUtility;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;
import ru.CryptoPro.XAdES.*;
import ru.CryptoPro.XAdES.transform.EnvelopedTransform;
import ru.CryptoPro.reprov.RevCheck;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Signer {
    public Signer() {
        JCPXMLDSigInit.init();  //без него XAdES не создаётся
        System.setProperty("com.sun.security.enableCRLDP", "true");
        System.setProperty("com.ibm.security.enableCRLDP", "true");
        System.setProperty("ocsp.enable", "true");
        // Security.setProperty("ocsp.responderURL", "http://testguc.voskhod.local/OCSP/ocsp.srf");
        System.setProperty("org.apache.xml.security.resource.config", "resource/jcp.xml");
        Security.addProvider(new JCP());
        Security.addProvider(new RevCheck());
        Init.init();
    }

    public byte[] CMS(String alias, String password, byte[] data, boolean detached) throws Exception {

        final KeyStore hdImageStore = KeyStore.getInstance(CMStools.STORE_TYPE);
        hdImageStore.load(null, null);
        X509Certificate certificate = (X509Certificate) hdImageStore.getCertificate(alias);
        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());
//
//        //определение алгоритма
//        CertAlgGeneration alg = new CertAlgGeneration(certificate);


//        final Signature signature = Signature.getInstance(alg.SIGN_NAME, JCP.PROVIDER_NAME);
//        signature.initSign(privateKey);
//        signature.update(data);
//        final byte[] sign = signature.sign();
//        return createCMSEx(data, sign, certificate, detached, alg.DIGEST_OID, alg.PARAMS_SIG_KEY_OID, alg.SIGN_NAME);
        return CMSSignEx(data, privateKey, certificate, detached, JCP.PROVIDER_NAME);
    }

    public byte[] XAdES_BES(String alias, String password, byte[] data, String ref_acct) throws Exception {

        // декодирование документа
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        Document document = dbFactory.newDocumentBuilder().parse(
                new ByteArrayInputStream(data));

        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();

        XPathExpression expr = xpath.compile(String.format("//*[@Id='%s']", ref_acct));
        NodeList nodes = (NodeList) expr.evaluate(document, XPathConstants.NODESET);

        if (nodes.getLength() == 0) {
            throw new Exception("Not found ID=" + ref_acct);
        }

        Node node = nodes.item(0);
        String referenceURI = "#" + ref_acct;


        // Подписываемая ссылка.
        DataObjects dataObjects = new DataObjects(Collections.singletonList(referenceURI));
        dataObjects.addTransform(new EnvelopedTransform());

        final KeyStore hdImageStore = KeyStore.getInstance(CMStools.STORE_TYPE);
        hdImageStore.load(null, null);
        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());

        Certificate[] chainArray = hdImageStore.getCertificateChain(alias);
        List<X509Certificate> chain = Stream.of(chainArray).map(it ->
                (X509Certificate) it).collect(Collectors.toList());

        XAdESSignature xAdESSignature = new XAdESSignature();
        xAdESSignature.addSigner(JCP.PROVIDER_NAME, null, privateKey, chain, XAdESType.XAdES_BES, null);

        ByteArrayOutputStream signatureStream = new ByteArrayOutputStream();

        xAdESSignature.open(signatureStream);
        xAdESSignature.update((Element) node, dataObjects);
        xAdESSignature.close();
        return signatureStream.toByteArray();
    }

    public byte[] XAdES_T(String alias, String password, byte[] data, String tsp, String ref_acct) throws Exception {
        // декодирование документа
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        Document document = dbFactory.newDocumentBuilder().parse(
                new ByteArrayInputStream(data));

        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();

        XPathExpression expr = xpath.compile(String.format("//*[@Id='%s']", ref_acct));
        NodeList nodes = (NodeList) expr.evaluate(document, XPathConstants.NODESET);

        if (nodes.getLength() == 0) {
            throw new Exception("Not found ID=" + ref_acct);
        }

        Node node = nodes.item(0);
        String referenceURI = "#" + ref_acct;

        // Подписываемая ссылка.
        DataObjects dataObjects = new DataObjects(Collections.singletonList(referenceURI));
        dataObjects.addTransform(new EnvelopedTransform());

        final KeyStore hdImageStore = KeyStore.getInstance(CMStools.STORE_TYPE);
        hdImageStore.load(null, null);
        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());

        Certificate[] chainArray = hdImageStore.getCertificateChain(alias);
        List<X509Certificate> chain = Stream.of(chainArray).map(it ->
                (X509Certificate) it).collect(Collectors.toList());

        XAdESSignature xAdESSignature = new XAdESSignature();
        xAdESSignature.addSigner(JCP.PROVIDER_NAME, null, null, null, privateKey, chain, false,
                XAdESType.XAdES_T, tsp, null);

        ByteArrayOutputStream signatureStream = new ByteArrayOutputStream();

        xAdESSignature.open(signatureStream);
        xAdESSignature.update((Element) node, dataObjects);
        xAdESSignature.close();
        return signatureStream.toByteArray();
    }

    public byte[] WS_Security(String alias, String password, byte[] data) throws Exception {
        return data;
    }

    public static byte[] createCMSEx1(byte[] buffer, byte[] sign, Certificate cert, boolean detached, String digestOid,
                                      String signOid, String signName) throws Exception {

        ContentInfo all = new ContentInfo();
        all.contentType = new Asn1ObjectIdentifier(new OID(CMStools.STR_CMS_OID_SIGNED).value);

        final SignedData cms = new SignedData();
        all.content = cms;
        cms.version = new CMSVersion(1);

        // digest
        cms.digestAlgorithms = new DigestAlgorithmIdentifiers(1);
        final DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier(new OID(digestOid).value);

        a.parameters = new Asn1Null();
        cms.digestAlgorithms.elements[0] = a;

        if (detached) {
            cms.encapContentInfo = new EncapsulatedContentInfo(
                    new Asn1ObjectIdentifier(new OID(CMStools.STR_CMS_OID_DATA).value), null);
        } // if
        else {
            cms.encapContentInfo = new EncapsulatedContentInfo(new Asn1ObjectIdentifier(
                    new OID(CMStools.STR_CMS_OID_DATA).value),
                    new Asn1OctetString(buffer));
        } // else

        // certificate
        cms.certificates = new CertificateSet(1);
        final ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate certificate =
                new ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate();
        final Asn1BerDecodeBuffer decodeBuffer =
                new Asn1BerDecodeBuffer(cert.getEncoded());
        certificate.decode(decodeBuffer);

        cms.certificates.elements = new CertificateChoices[1];
        cms.certificates.elements[0] = new CertificateChoices();
        cms.certificates.elements[0].set_certificate(certificate);

        // signer info
        cms.signerInfos = new SignerInfos(1);
        cms.signerInfos.elements[0] = new SignerInfo();
        cms.signerInfos.elements[0].version = new CMSVersion(1);
        cms.signerInfos.elements[0].sid = new SignerIdentifier();

        final byte[] encodedName = ((X509Certificate) cert).getIssuerX500Principal().getEncoded();
        final Asn1BerDecodeBuffer nameBuf = new Asn1BerDecodeBuffer(encodedName);
        final Name name = new Name();
        name.decode(nameBuf);
        final CertificateSerialNumber num = new CertificateSerialNumber(((X509Certificate) cert).getSerialNumber());
        cms.signerInfos.elements[0].sid.set_issuerAndSerialNumber(new IssuerAndSerialNumber(name, num));
        cms.signerInfos.elements[0].digestAlgorithm = new DigestAlgorithmIdentifier(new OID(digestOid).value);
        cms.signerInfos.elements[0].digestAlgorithm.parameters = new Asn1Null();
        cms.signerInfos.elements[0].signatureAlgorithm = new SignatureAlgorithmIdentifier(new OID(signOid).value);
        cms.signerInfos.elements[0].signatureAlgorithm.parameters = new Asn1Null();
        cms.signerInfos.elements[0].signature = new SignatureValue(sign);

        // encode
        final Asn1BerEncodeBuffer asnBuf = new Asn1BerEncodeBuffer();
        all.encode(asnBuf, true);

        // byte[] digest = messageDigest.digest(asnBuf.getMsgCopy());
        MessageDigest digest =
                (GostDigest) MessageDigest.getInstance(JCP.GOST_DIGEST_NAME, JCP.PROVIDER_NAME);
        digest.update(buffer);
        //System.out.println(new Asn1OctetString(String.valueOf(digest)));
        return asnBuf.getMsgCopy();
    }


    public static byte[] CMSSign(byte[] data, PrivateKey key,
                                 Certificate cert, boolean detached) throws Exception {
        return CMSSignEx(data, key, cert, detached, JCP.PROVIDER_NAME);
    }

    public static byte[] CMSSignEx(byte[] data, PrivateKey key,
                                   Certificate cert, boolean detached, String providerName)
            throws Exception {

        String keyAlg = key.getAlgorithm();
        String signOid = AlgorithmUtility.keyAlgToSignatureOid(keyAlg);

        // sign
        final Signature signature = Signature.getInstance(signOid, providerName);
        signature.initSign(key);
        signature.update(data);

        final byte[] sign = signature.sign();

        // create cms format
        return createCMSEx(data, sign, cert, detached);
    }

    public static byte[] createCMSEx(byte[] buffer, byte[] sign,
                                     Certificate cert, boolean detached) throws Exception {

        String pubKeyAlg = cert.getPublicKey().getAlgorithm();
        String digestOid = AlgorithmUtility.keyAlgToDigestOid(pubKeyAlg);
        String keyOid = AlgorithmUtility.keyAlgToKeyAlgorithmOid(pubKeyAlg); // алгоритм ключа подписи

        final ContentInfo all = new ContentInfo();
        all.contentType = new Asn1ObjectIdentifier(
                new OID(CMStools.STR_CMS_OID_SIGNED).value);

        final SignedData cms = new SignedData();
        all.content = cms;
        cms.version = new CMSVersion(1);

        // digest
        cms.digestAlgorithms = new DigestAlgorithmIdentifiers(1);
        final DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier(
                new OID(digestOid).value);

        a.parameters = new Asn1Null();
        cms.digestAlgorithms.elements[0] = a;

        if (detached) {
            cms.encapContentInfo = new EncapsulatedContentInfo(
                    new Asn1ObjectIdentifier(
                            new OID(CMStools.STR_CMS_OID_DATA).value), null);
        } // if
        else {
            cms.encapContentInfo =
                    new EncapsulatedContentInfo(new Asn1ObjectIdentifier(
                            new OID(CMStools.STR_CMS_OID_DATA).value),
                            new Asn1OctetString(buffer));
        } // else

        // certificate
        cms.certificates = new CertificateSet(1);
        final ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate certificate =
                new ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate();
        final Asn1BerDecodeBuffer decodeBuffer =
                new Asn1BerDecodeBuffer(cert.getEncoded());
        certificate.decode(decodeBuffer);

        cms.certificates.elements = new CertificateChoices[1];
        cms.certificates.elements[0] = new CertificateChoices();
        cms.certificates.elements[0].set_certificate(certificate);

        // signer info
        cms.signerInfos = new SignerInfos(1);
        cms.signerInfos.elements[0] = new SignerInfo();
        cms.signerInfos.elements[0].version = new CMSVersion(1);
        cms.signerInfos.elements[0].sid = new SignerIdentifier();

        final byte[] encodedName = ((X509Certificate) cert)
                .getIssuerX500Principal().getEncoded();
        final Asn1BerDecodeBuffer nameBuf = new Asn1BerDecodeBuffer(encodedName);
        final Name name = new Name();
        name.decode(nameBuf);

        final CertificateSerialNumber num = new CertificateSerialNumber(
                ((X509Certificate) cert).getSerialNumber());
        cms.signerInfos.elements[0].sid.set_issuerAndSerialNumber(
                new IssuerAndSerialNumber(name, num));
        cms.signerInfos.elements[0].digestAlgorithm =
                new DigestAlgorithmIdentifier(new OID(digestOid).value);
        cms.signerInfos.elements[0].digestAlgorithm.parameters = new Asn1Null();
        cms.signerInfos.elements[0].signatureAlgorithm =
                new SignatureAlgorithmIdentifier(new OID(keyOid).value);
        cms.signerInfos.elements[0].signatureAlgorithm.parameters = new Asn1Null();
        cms.signerInfos.elements[0].signature = new SignatureValue(sign);

        // encode
        final Asn1BerEncodeBuffer asnBuf = new Asn1BerEncodeBuffer();
        all.encode(asnBuf, true);
        return asnBuf.getMsgCopy();
    }
}
