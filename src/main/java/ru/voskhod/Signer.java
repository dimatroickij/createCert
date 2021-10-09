package ru.voskhod;

import com.sun.org.apache.xml.internal.security.Init;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.CollectionStore;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;
import ru.CryptoPro.XAdES.DataObjects;
import ru.CryptoPro.XAdES.XAdESSignature;
import ru.CryptoPro.XAdES.XAdESType;
import ru.CryptoPro.XAdES.transform.EnvelopedTransform;
import ru.CryptoPro.reprov.RevCheck;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Signer {
    public Signer() {
        JCPXMLDSigInit.init();  //без него XAdES не создаётся
        System.setProperty("ru.CryptoPro.reprov.enableCRLDP", "true");
        System.setProperty("com.sun.security.enableCRLDP", "true");
        System.setProperty("com.ibm.security.enableCRLDP", "true");
        System.setProperty("ru.cryptopro.notThrowIfChainIsInvalid", "true");
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

        //определение алгоритма
        CertAlgGeneration alg = new CertAlgGeneration(certificate);

        return CMS.CMSSignEx(data, privateKey, certificate, detached, alg.DIGEST_OID, alg.PARAMS_SIG_KEY_OID, alg.SIGN_NAME, alg.PROVIDER_NAME);
    }

    // Подумать про отсоединённую подпись
    public byte[] CAdES_BES(String alias, String password, byte[] data, boolean detached) throws Exception {

        final KeyStore hdImageStore = KeyStore.getInstance(CMStools.STORE_TYPE);
        hdImageStore.load(null, null);
        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());

        Certificate[] chainArray = hdImageStore.getCertificateChain(alias);
        List<X509Certificate> chain = Stream.of(chainArray).map(it -> (X509Certificate) it).collect(Collectors.toList());

        // Создаем CAdES подпись.
        CAdESSignature cadesSignature = new CAdESSignature(detached);
        cadesSignature.addSigner(JCP.PROVIDER_NAME, null, null, privateKey, chain, CAdESType.CAdES_BES, null, false);

        // Добавление цепочки сертификатов в созданную подпись
        List<X509CertificateHolder> chainHolder = new ArrayList<>();
        chainHolder.add(new X509CertificateHolder(hdImageStore.getCertificate(alias).getEncoded()));
        for (Certificate s : chainArray) {
            chainHolder.add(new X509CertificateHolder(s.getEncoded()));
        }
        CollectionStore collectionStore = new CollectionStore(chainHolder);
        cadesSignature.setCertificateStore(collectionStore);

        //Будущая подпись в виде массива.
        ByteArrayOutputStream signatureStream = new ByteArrayOutputStream();
        cadesSignature.open(signatureStream); // подготовка контекста
        cadesSignature.update(data); // хеширование
        cadesSignature.close(); // создание подписи с выводом в signatureStream
        signatureStream.close();

        return signatureStream.toByteArray();
    }

//    public byte[] CAdES_T(String alias, String password, byte[] data, String tsp, boolean detached) throws Exception {
//        Security.addProvider(new JCP());
//        Security.addProvider(new RevCheck());
//        System.setProperty("com.sun.security.enableCRLDP", "true");
//        System.setProperty("com.ibm.security.enableCRLDP", "true");
//        System.setProperty("com.sun.security.enableAIAcaIssuers", "true");
//
//        final KeyStore hdImageStore = KeyStore.getInstance(CMStools.STORE_TYPE);
//        hdImageStore.load(null, null);
//        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());
//
//        Certificate[] chainArray = hdImageStore.getCertificateChain(alias);
//        List<X509Certificate> chain = Stream.of(chainArray).map(it -> (X509Certificate) it).collect(Collectors.toList());
//
//        // Создаем CAdES-X Long Type 1 подпись.
//        CAdESSignature cadesSignature = new CAdESSignature(detached);
//        cadesSignature.addSigner(JCP.PROVIDER_NAME, null, null, privateKey, chain, CAdESType.CAdES_T,
//                tsp, false);
//
//        // Добавление цепочки сертификатов в созданную подпись
//        List<X509CertificateHolder> chainHolder = new ArrayList<>();
//        chainHolder.add(new X509CertificateHolder(hdImageStore.getCertificate(alias).getEncoded()));
//        for (Certificate s : chainArray) {
//            chainHolder.add(new X509CertificateHolder(s.getEncoded()));
//        }
//        CollectionStore collectionStore = new CollectionStore(chainHolder);
//        cadesSignature.setCertificateStore(collectionStore);
//
//        //Будущая подпись в виде массива.
//        ByteArrayOutputStream signatureStream = new ByteArrayOutputStream();
//        cadesSignature.open(signatureStream); // подготовка контекста
//        cadesSignature.update(data); // хеширование
//        cadesSignature.close(); // создание подписи с выводом в signatureStream
//        signatureStream.close();
//
//        return signatureStream.toByteArray();
//    }

    public byte[] CAdES_X_LONG_TYPE_1(String alias, String password, byte[] data, String tsp, boolean detached) throws Exception {
        final KeyStore hdImageStore = KeyStore.getInstance(CMStools.STORE_TYPE);
        hdImageStore.load(null, null);
        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());

        Certificate[] chainArray = hdImageStore.getCertificateChain(alias);
        List<X509Certificate> chain = Stream.of(chainArray).map(it -> (X509Certificate) it).collect(Collectors.toList());

        // Создаем CAdES-X Long Type 1 подпись.
        CAdESSignature cadesSignature = new CAdESSignature(detached);
        cadesSignature.addSigner(JCP.PROVIDER_NAME, null, null, privateKey, chain, CAdESType.CAdES_X_Long_Type_1,
                tsp, false);

        // Добавление цепочки сертификатов в созданную подпись
        List<X509CertificateHolder> chainHolder = new ArrayList<>();
        chainHolder.add(new X509CertificateHolder(hdImageStore.getCertificate(alias).getEncoded()));
        for (Certificate s : chainArray) {
            chainHolder.add(new X509CertificateHolder(s.getEncoded()));
        }
        CollectionStore collectionStore = new CollectionStore(chainHolder);
        cadesSignature.setCertificateStore(collectionStore);

        //Будущая подпись в виде массива.
        ByteArrayOutputStream signatureStream = new ByteArrayOutputStream();
        cadesSignature.open(signatureStream); // подготовка контекста
        cadesSignature.update(data); // хеширование
        cadesSignature.close(); // создание подписи с выводом в signatureStream
        signatureStream.close();

        return signatureStream.toByteArray();
    }

    public byte[] XAdES_BES (String alias, String password, byte[] data) throws Exception {
        String documentContext = new String(data);
        String ref_acct = "bank";

        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        Document document = dbFactory.newDocumentBuilder().parse(
                new ByteArrayInputStream(documentContext.getBytes(StandardCharsets.UTF_8)));
        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();
        XPathExpression expr = xpath.compile(String.format("//*[@Id='%s']", ref_acct));
        NodeList nodes = (NodeList) expr.evaluate(document, XPathConstants.NODESET);
        Node node = nodes.item(0);
        String referenceURI = "#" + ref_acct;
        // Подписываемая ссылка.
        DataObjects dataObjects = new DataObjects(Arrays.asList(referenceURI));
        dataObjects.addTransform(new EnvelopedTransform());

        final KeyStore hdImageStore = KeyStore.getInstance(CMStools.STORE_TYPE);
        hdImageStore.load(null, null);
        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());

        Certificate[] chainArray = hdImageStore.getCertificateChain(alias);
        List<X509Certificate> chain = Stream.of(chainArray).map(it -> (X509Certificate) it).collect(Collectors.toList());

        XAdESSignature xAdESSignature = new XAdESSignature();
        xAdESSignature.addSigner(JCP.PROVIDER_NAME, null, privateKey, chain, XAdESType.XAdES_BES, null);

//        xAdESSignature.open(fileOutputStream);
//        xAdESSignature.update((Element) node, dataObjects);
//        xAdESSignature.close();
        ByteArrayOutputStream signatureStream = new ByteArrayOutputStream();
        xAdESSignature.open(signatureStream);
        xAdESSignature.update((Element) node, dataObjects);
        xAdESSignature.close();
        signatureStream.toByteArray();
        return signatureStream.toByteArray();
    }
}
