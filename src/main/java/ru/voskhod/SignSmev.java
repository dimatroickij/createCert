/*
 * Decompiled with CFR 0_129.
 * 
 * Could not load the following classes:
 *  org.apache.commons.codec.binary.Base64
 *  org.apache.xml.security.Init
 *  org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException
 *  org.apache.xml.security.keys.KeyInfo
 *  org.apache.xml.security.signature.XMLSignature
 *  org.apache.xml.security.transforms.Transform
 *  org.apache.xml.security.transforms.Transforms
 *  ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit
 */
package ru.voskhod;


import org.apache.xml.security.Init;
import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.InvalidTransformException;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.Transforms;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.*;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;
import sun.security.pkcs.*;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class SignSmev {

    
    private static final String EDS_ERROR_SIGNATURE_INVALID = "\u041e\u0448\u0438\u0431\u043a\u0430 \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0438 \u042d\u041f: \u041d\u0430\u0440\u0443\u0448\u0435\u043d\u0430 \u0446\u0435\u043b\u043e\u0441\u0442\u043d\u043e\u0441\u0442\u044c \u042d\u041f";
    private static final String EDS_ERROR_PUBLIC_KEY_IS_NOT_FOUND = "\u041d\u0435\u0442 \u0438\u043d\u0444\u043e\u0440\u043c\u0430\u0446\u0438\u0438 \u043e\u0431 \u043e\u0442\u043a\u0440\u044b\u0442\u043e\u043c \u043a\u043b\u044e\u0447\u0435. \u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u043d\u0435 \u043c\u043e\u0436\u0435\u0442 \u0431\u044b\u0442\u044c \u043e\u0441\u0443\u0449\u0435\u0441\u0442\u0432\u043b\u0435\u043d\u0430.";



    private static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    //private static final String GOST_EL_SIGN_NAME = "GOST3411withGOST3410EL";
    private static final String GOST_EL_SIGN_NAME = "GOST3410_2012_256";
    //private static final String SIGN_OID = "1.2.643.2.2.19";
    private static final String SIGN_OID = "1.2.643.7.1.1.1.1";
    private static final String XMLDSIG_DETACHED_TRANSFORM_METHOD = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private static final String SMEV_TRANSFORM_METHOD = "urn://smev-gov-ru/xmldsig/transform";
    //private static final String DIGEST_METHOD = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";
    private static final String DIGEST_METHOD = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
    //private static final String XMLDSIG_SIGN_METHOD = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";
    private static final String XMLDSIG_SIGN_METHOD = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";


    private static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String WSSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private static final int BUFFER_SIZE = 8192;

    private static SignSmev instance;
    private static Map<Map<String, String>, SignSmev> signDataInsMap;
    private KeyStore keyStore = null;
    private PrivateKey privateKey = null;
    private X509Certificate cert;
    private DocumentBuilder builder = null;
    private Transformer transformer = null;
    private String digest;
    private static ThreadLocal<TransformerFactory> transformerFactory;
    private static ThreadLocal<DocumentBuilderFactory> documentBuilderFactory;

    public static SignSmev getInstance(Map<String, String> params) {
        instance = signDataInsMap.get(params);
        if (instance == null) {
            instance = new SignSmev(params);
            signDataInsMap.put(params, instance);
        }
        return instance;
    }

    private SignSmev(Map<String, String> params) {
        try {



                this.keyStore = KeyStore.getInstance(params.get("storeName"));
                this.keyStore.load(null, null);
                this.cert = (X509Certificate)this.keyStore.getCertificate(params.get("alias"));

            this.privateKey = (PrivateKey)this.keyStore.getKey(params.get("alias"), params.get("password").toCharArray());
            this.builder = documentBuilderFactory.get().newDocumentBuilder();
            this.transformer = transformerFactory.get().newTransformer();
            this.transformer.setOutputProperty("omit-xml-declaration", "yes");
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public String signXml(String data) throws Exception {
        Element content2sign = this.getBusinessContent(data);
        Document argDocument = content2sign.getOwnerDocument();
        String referenceURI = content2sign.getAttribute("Id");
        if (referenceURI == null || "".equals(referenceURI.trim())) {
            referenceURI = content2sign.getAttributeNS(WSSU_NS, "Id");
        }
        if ("".equals(referenceURI.trim())) {
            referenceURI = "";
        }
        XMLSignature xmlSignature = new XMLSignature(argDocument, "", XMLDSIG_SIGN_METHOD, XMLDSIG_DETACHED_TRANSFORM_METHOD);
        Transforms transforms = new Transforms(argDocument);
        transforms.addTransform(XMLDSIG_DETACHED_TRANSFORM_METHOD);
        transforms.addTransform(SMEV_TRANSFORM_METHOD);
        String refURI = referenceURI;
        if (refURI != null && !refURI.isEmpty() && !refURI.startsWith("#")) {
            refURI = "#" + refURI;
        }
        xmlSignature.addDocument(refURI, transforms, DIGEST_METHOD);
        xmlSignature.addKeyInfo(this.cert);
        xmlSignature.sign(this.privateKey);
        StringWriter writer = null;
        try {
            writer = new StringWriter();
            DOMSource domSource = new DOMSource(xmlSignature.getElement());
            StreamResult result = new StreamResult(writer);
            Object object =  this.transformer;
            synchronized (object) {
                this.transformer.transform(domSource, result);
            }
            writer.flush();
            object =  writer.toString();
            return  (String) object;
        }
        finally {
            try {
                writer.close();
            }
            catch (IOException e) {}
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public byte[] signPKCS7(InputStream inputStream) throws Exception {
        String pathNewFileName = "attach_" + System.currentTimeMillis();
        File newFileName = new File(pathNewFileName);
        try {
            byte[] digestedContent = this.getDigest(inputStream, newFileName);
            AlgorithmId[] digestAlgorithmIds = new AlgorithmId[]{AlgorithmId.get("1.2.643.2.2.9")};
            PKCS9Attribute[] authenticatedAttributeList = new PKCS9Attribute[]{new PKCS9Attribute(PKCS9Attribute.CONTENT_TYPE_OID, (Object)ContentInfo.DATA_OID), new PKCS9Attribute(PKCS9Attribute.SIGNING_TIME_OID, (Object)new Date()), new PKCS9Attribute(PKCS9Attribute.MESSAGE_DIGEST_OID, (Object)digestedContent)};
            PKCS9Attributes authenticatedAttributes = new PKCS9Attributes(authenticatedAttributeList);
            byte[] signedAttributes = this.sign(this.privateKey, authenticatedAttributes.getDerEncoding());
            ContentInfo contentInfo = new ContentInfo(ContentInfo.DATA_OID, null);
            X509Certificate[] certificates = new X509Certificate[]{this.cert};
            BigInteger serial = this.cert.getSerialNumber();
            SignerInfo si = new SignerInfo(new X500Name(this.cert.getIssuerDN().getName()), serial, AlgorithmId.get("1.2.643.2.2.9"), authenticatedAttributes, new AlgorithmId(new ObjectIdentifier(SIGN_OID)), signedAttributes, null);
            SignerInfo[] signerInfos = new SignerInfo[]{si};
            PKCS7 p7 = new PKCS7(digestAlgorithmIds, contentInfo, certificates, signerInfos);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            p7.encodeSignedData(bos);
            byte[] arrby = bos.toByteArray();
            return arrby;
        }
        finally {
            newFileName.delete();
        }
    }

    private synchronized byte[] getDigest(InputStream inputStream, File newFileName) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("GOST3411");
        int read = 0;
        byte[] buf = new byte[8192];
        while ((read = inputStream.read(buf)) != -1) {
            digest.update(buf, 0, read);
        }
        byte[] digestedContent = digest.digest();
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(digestedContent);
        CopyOption[] opts = new StandardCopyOption[]{StandardCopyOption.REPLACE_EXISTING};
        Files.copy(byteArrayInputStream, newFileName.toPath(), opts);
        inputStream.close();
        byteArrayInputStream.close();
        this.digest = Base64.toBase64String((byte[])digestedContent);
        return digestedContent;
    }

    public byte[] sign(PrivateKey key, byte[] data) throws Exception {
        Signature signer = null;
        signer = Signature.getInstance(GOST_EL_SIGN_NAME);
        signer.initSign(key);
        signer.update(data);
        return signer.sign();
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public Element getBusinessContent(String data) throws Exception {
        Document doc = null;
        DocumentBuilder documentBuilder = this.builder;
        synchronized (documentBuilder) {
            doc = this.builder.parse(new ByteArrayInputStream(data.getBytes("UTF-8")));
        }
        return doc.getDocumentElement();
    }

    public boolean validationSignXML(String content, String signatureXML) throws Exception {
        Element signatureElement;
        Element keyInfoAsDOM;
        Document tmpDocument;
        Element referenceToCertificate;
        Element argSignedContent = this.getBusinessContent(content);
        Element argSignatureElement = this.getBusinessContent(signatureXML);
        if (argSignedContent == null) {
            throw new Exception("\u041f\u043e\u0434\u043f\u0438\u0441\u0430\u043d\u043d\u044b\u0439 XML-\u0444\u0440\u0430\u0433\u043c\u0435\u043d\u0442 \u043d\u0435 \u043f\u0435\u0440\u0435\u0434\u0430\u043d.");
        }
        if (!(argSignatureElement == null || XMLDSIG_NS.equals(argSignatureElement.getNamespaceURI()) && "Signature".equals(argSignatureElement.getLocalName()))) {
            throw new Exception("\u041a\u043e\u0440\u043d\u0435\u0432\u043e\u0439 \u044d\u043b\u0435\u043c\u0435\u043d\u0442 detached-\u043f\u043e\u0434\u043f\u0438\u0441\u0438 \u0438\u043c\u0435\u0435\u0442 \u043f\u043e\u043b\u043d\u043e\u0435 \u0438\u043c\u044f, \u043e\u0442\u043b\u0438\u0447\u043d\u043e\u0435 \u043e\u0442 {http://www.w3.org/2000/09/xmldsig#}.Signature");
        }
        boolean emptyRefURI = false;
        Element element = signatureElement = argSignatureElement != null ? argSignatureElement : this.findSignatureElement(argSignedContent);
        if (signatureElement == null) {
            throw new Exception("\u041d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d \u044d\u043b\u0435\u043c\u0435\u043d\u0442 {http://www.w3.org/2000/09/xmldsig#}.Signature");
        }
        NodeList nl = signatureElement.getElementsByTagNameNS(XMLDSIG_NS, "Reference");
        if (nl.getLength() > 0) {
            Element ref = (Element)nl.item(0);
            Attr uri = ref.getAttributeNode("URI");
            boolean bl = emptyRefURI = uri == null || "".equals(uri.getNodeValue());
        }
        if (argSignatureElement != null && argSignedContent.getOwnerDocument() != argSignatureElement.getOwnerDocument()) {
            tmpDocument = this.builder.newDocument();
            Element tmpDocumentRootElement = (Element)tmpDocument.appendChild(tmpDocument.createElement("root_validator"));
            signatureElement = (Element)tmpDocumentRootElement.appendChild(tmpDocument.importNode(argSignatureElement, true));
            tmpDocumentRootElement.appendChild(tmpDocument.importNode(argSignedContent, true));
            tmpDocument.normalizeDocument();
        } else if (argSignatureElement == null && (signatureElement.getParentNode() != argSignedContent || emptyRefURI)) {
            tmpDocument = this.builder.newDocument();
            Node importedSignatureParent = tmpDocument.importNode(signatureElement.getParentNode(), true);
            tmpDocument.appendChild(importedSignatureParent);
            tmpDocument.normalizeDocument();
            signatureElement = this.findSignatureElement(tmpDocument);
        }
        XMLSignature signature = new XMLSignature(signatureElement, "");
        KeyInfo keyInfoFromSignature = signature.getKeyInfo();
        X509Certificate certificate = keyInfoFromSignature.getX509Certificate();
        if (certificate == null && (keyInfoAsDOM = this.getUniqueChildElement(signatureElement, XMLDSIG_NS, "KeyInfo")) != null && (referenceToCertificate = this.getUniqueChildElement(keyInfoAsDOM, WSSE_NS, "Reference")) != null) {
            String certificateURI = referenceToCertificate.getAttribute("URI").substring(1);
            Element certificateBinaryToken = signatureElement.getOwnerDocument().getElementById(certificateURI);
            byte[] certificateAsByteArray = Base64.decode((byte[])certificateBinaryToken.getTextContent().getBytes("UTF-8"));
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certificateAsByteArray));
        }
        if (certificate != null) {
            boolean signatureIsValid = signature.checkSignatureValue(certificate);
            if (!signatureIsValid) {
                throw new IllegalArgumentException(EDS_ERROR_SIGNATURE_INVALID);
            }
        } else {
            PublicKey publicKeyFromSignature = keyInfoFromSignature.getPublicKey();
            if (publicKeyFromSignature != null) {
                boolean signatureIsValid = signature.checkSignatureValue((Key)publicKeyFromSignature);
                if (!signatureIsValid) {
                    throw new Exception(EDS_ERROR_SIGNATURE_INVALID);
                }
            } else {
                throw new Exception(EDS_ERROR_PUBLIC_KEY_IS_NOT_FOUND);
            }
        }
        certificate.checkValidity();
        return true;
    }

    private Element getUniqueChildElement(Element argParent, String argNamespaceURI, String argLocalName) {
        NodeList nodeList = argParent.getElementsByTagNameNS(argNamespaceURI, argLocalName);
        if (nodeList.getLength() > 0) {
            return (Element)nodeList.item(0);
        }
        return null;
    }

    private Element findSignatureElement(Node signedDoc) throws Exception {
        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();
        //xpath.setNamespaceContext(new SignatureNamespaceContext());
        XPathExpression sigXP = xpath.compile("//ds:Signature[1]");
        Element sigElement = (Element)sigXP.evaluate(signedDoc, XPathConstants.NODE);
        if (sigElement == null) {
            throw new Exception();
        }
        return sigElement;
    }

    public String getDigest() {
        return this.digest;
    }



    static {
        Init.init();
        signDataInsMap = new HashMap<Map<String, String>, SignSmev>();

            System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
            Init.init();
            JCPXMLDSigInit.init();

//        try {
//            System.out.println("d");
//            //Transform.register((String)SMEV_TRANSFORM_METHOD, (String)SmevTransformSpi.class.getName());
//        }
//        catch (AlgorithmAlreadyRegisteredException e) {
//            System.out.println("Failed to register transform algorithm for urn://smev-gov-ru/xmldsig/transform");
//            System.err.println((Object)e);
//        } catch (InvalidTransformException | ClassNotFoundException e) {
//            e.printStackTrace();
//        }
        transformerFactory = new ThreadLocal<TransformerFactory>(){

            @Override
            protected TransformerFactory initialValue() {
                return TransformerFactory.newInstance();
            }
        };
        documentBuilderFactory = new ThreadLocal<DocumentBuilderFactory>(){

            @Override
            protected DocumentBuilderFactory initialValue() {
                DocumentBuilderFactory result = DocumentBuilderFactory.newInstance();
                result.setNamespaceAware(true);
                result.setCoalescing(true);
                result.setIgnoringElementContentWhitespace(true);
                return result;
            }
        };
    }

}

