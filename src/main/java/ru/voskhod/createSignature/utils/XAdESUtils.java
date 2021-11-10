package ru.voskhod.createSignature.utils;

import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.XAdES.DataObjects;
import ru.CryptoPro.XAdES.XAdESSignature;
import ru.CryptoPro.XAdES.XAdESType;
import ru.CryptoPro.XAdES.transform.EnvelopedTransform;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class XAdESUtils {

    static String VerifyXAdES = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyXAdES>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyXAdES>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    static String VerifyXAdESWithReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyXAdESWithReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyXAdESWithReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    static String VerifyXAdESWithSignedReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyXAdESWithSignedReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyXAdESWithSignedReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    // TODO не работает со Strong подписями
    public static byte[] createXAdES(byte[] data, String alias, String password, String tsp, String ref_acct,
                                     Integer TypeXAdES) throws Exception {
        KeyStore hdImageStore = KeyStore.getInstance(JCP.HD_STORE_NAME, JCP.PROVIDER_NAME);
        hdImageStore.load(null, null);

        // декодирование документа
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        Document document = dbFactory.newDocumentBuilder().parse(new ByteArrayInputStream(data));

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

        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());

        Certificate[] chainArray = hdImageStore.getCertificateChain(alias);
        List<X509Certificate> chain = Stream.of(chainArray).map(it ->
                (X509Certificate) it).collect(Collectors.toList());

        XAdESSignature xAdESSignature = new XAdESSignature();

        if (Objects.equals(TypeXAdES, XAdESType.XAdES_BES))
            xAdESSignature.addSigner(JCP.PROVIDER_NAME, null, privateKey, chain, TypeXAdES, null);
        else
            xAdESSignature.addSigner(JCP.PROVIDER_NAME, null, null, null, privateKey, chain, false,
                    TypeXAdES, tsp, null);

        ByteArrayOutputStream signatureStream = new ByteArrayOutputStream();

        xAdESSignature.open(signatureStream);
        xAdESSignature.update((Element) node, dataObjects);
        xAdESSignature.close();
        return signatureStream.toByteArray();
    }

    public static byte[] createVerifyXAdES(byte[] data, Integer TypeXAdES, boolean verifySignatureOnly)
            throws Exception {
        return createVerifyXAdES(data, null, null, null, null,
                TypeXAdES, verifySignatureOnly, true);
    }

    public static byte[] createVerifyXAdES(byte[] data, String alias, String password, String tsp, String ref_acct,
                                           Integer TypeXAdES, boolean verifySignatureOnly) throws Exception {
        return createVerifyXAdES(data, alias, password, tsp, ref_acct, TypeXAdES, verifySignatureOnly, false);
    }

    static byte[] createVerifyXAdES(byte[] data, String alias, String password, String tsp, String ref_acct,
                                    Integer TypeXAdES, boolean verifySignatureOnly,
                                    boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createXAdES(data, alias, password, tsp, ref_acct, TypeXAdES);
        }
        if (Objects.equals(TypeXAdES, XAdESType.XAdES_T))
            return VerifyXAdES.replace("{%message%}", Base64.toBase64String(data))
                    .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                    .getBytes(StandardCharsets.UTF_8);
        else
            return XMLUtils.VerifyXMLSignature.replace("{%message%}", Base64.toBase64String(data))
                    .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                    .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyXAdESWithReport(byte[] data, Integer TypeXAdES, boolean verifySignatureOnly)
            throws Exception {
        return createVerifyXAdESWithReport(data, null, null, null, null,
                TypeXAdES, verifySignatureOnly, true);
    }

    public static byte[] createVerifyXAdESWithReport(byte[] data, String alias, String password, String tsp,
                                                     String ref_acct, Integer TypeXAdES,
                                                     boolean verifySignatureOnly) throws Exception {
        return createVerifyXAdESWithReport(data, alias, password, tsp, ref_acct, TypeXAdES,
                verifySignatureOnly, false);
    }

    static byte[] createVerifyXAdESWithReport(byte[] data, String alias, String password, String tsp,
                                              String ref_acct, Integer TypeXAdES, boolean verifySignatureOnly,
                                              boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createXAdES(data, alias, password, tsp, ref_acct, TypeXAdES);
        }
        if (Objects.equals(TypeXAdES, XAdESType.XAdES_T))
            return VerifyXAdESWithReport.replace("{%message%}", Base64.toBase64String(data))
                    .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                    .getBytes(StandardCharsets.UTF_8);
        else
            return XMLUtils.VerifyXMLSignatureWithReport.replace("{%message%}", Base64.toBase64String(data))
                    .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                    .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyXAdESWithSignedReport(byte[] data, Integer TypeXAdES, boolean verifySignatureOnly)
            throws Exception {
        return createVerifyXAdESWithSignedReport(data, null, null, null, null,
                TypeXAdES, verifySignatureOnly, true);
    }

    public static byte[] createVerifyXAdESWithSignedReport(byte[] data, String alias, String password, String tsp,
                                                           String ref_acct, Integer TypeXAdES,
                                                           boolean verifySignatureOnly) throws Exception {
        return createVerifyXAdESWithSignedReport(data, alias, password, tsp, ref_acct, TypeXAdES,
                verifySignatureOnly, false);
    }

    static byte[] createVerifyXAdESWithSignedReport(byte[] data, String alias, String password,
                                                    String tsp, String ref_acct, Integer TypeXAdES,
                                                    boolean verifySignatureOnly,
                                                    boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createXAdES(data, alias, password, tsp, ref_acct, TypeXAdES);
        }
        if (Objects.equals(TypeXAdES, XAdESType.XAdES_T))
            return VerifyXAdESWithSignedReport.replace("{%message%}", Base64.toBase64String(data))
                    .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                    .getBytes(StandardCharsets.UTF_8);
        else
            return XMLUtils.VerifyXMLSignatureWithSignedReport.replace("{%message%}", Base64.toBase64String(data))
                    .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                    .getBytes(StandardCharsets.UTF_8);
    }

}
