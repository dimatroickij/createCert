package ru.voskhod.createSignature.controller;

import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.sun.org.apache.xml.internal.security.Init;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.java.Log;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.CollectionStore;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.tools.AlgorithmUtility;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;
import ru.CryptoPro.XAdES.DataObjects;
import ru.CryptoPro.XAdES.XAdESSignature;
import ru.CryptoPro.XAdES.XAdESType;
import ru.CryptoPro.XAdES.transform.EnvelopedTransform;
import ru.CryptoPro.reprov.RevCheck;
import ru.voskhod.createSignature.utils.CMSprocessing;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.*;
import java.security.*;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@RequestMapping("/signature")
@Log
@Tag(name = "Signature", description = "Работа с подписями")
public class SignatureController {
    KeyStore hdImageStore = KeyStore.getInstance(JCP.HD_STORE_NAME, JCP.PROVIDER_NAME);

    public SignatureController() throws KeyStoreException, NoSuchProviderException, CertificateException, IOException, NoSuchAlgorithmException {
        JCPXMLDSigInit.init();  //без него XAdES не создаётся
        System.setProperty("com.sun.security.enableCRLDP", "true");
        System.setProperty("com.ibm.security.enableCRLDP", "true");
        System.setProperty("ocsp.enable", "true");
        System.setProperty("org.apache.xml.security.resource.config", "resource/jcp.xml");
        Security.addProvider(new JCP());
        Security.addProvider(new RevCheck());
        Init.init();
        hdImageStore.load(null, null);
    }


    @Operation(summary = "Создание подписи CAdES-BES")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/pkcs7-signature")})})
    @PostMapping(value = "/cades_bes")
    public byte[] CAdES_BES(@RequestBody byte[] data,
                            @RequestParam(value = "alias") String alias,
                            @RequestParam(value = "password") String password,
                            @RequestParam(value = "detached") boolean detached) throws Exception {
        return createCAdES(data, alias, password, null, detached, CAdESType.CAdES_BES);
    }

    @Operation(summary = "Создание подписи CAdES-T")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/pkcs7-signature")})})
    @PostMapping(value = "/cades_t")
    public byte[] CAdES_T(@RequestBody byte[] data,
                          @RequestParam(value = "alias") String alias,
                          @RequestParam(value = "password") String password,
                          @RequestParam(value = "tsp") String tsp,
                          @RequestParam(value = "detached") boolean detached) throws Exception {
        return createCAdES(data, alias, password, tsp, detached, CAdESType.CAdES_T);
    }

    @Operation(summary = "Создание подписи CAdES-X-Long-Type 1")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/pkcs7-signature")})})
    @PostMapping(value = "/cades_x")
    public byte[] CAdES_X(@RequestBody byte[] data,
                          @RequestParam(value = "alias") String alias,
                          @RequestParam(value = "password") String password,
                          @RequestParam(value = "tsp") String tsp,
                          @RequestParam(value = "detached") boolean detached) throws Exception {
        return createCAdES(data, alias, password, tsp, detached, CAdESType.CAdES_X_Long_Type_1);
    }

    private byte[] createCAdES(byte[] data, String alias, String password, String tsp, boolean detached,
                               Integer TypeCades) throws Exception {
        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());
        Certificate[] chainArray = hdImageStore.getCertificateChain(alias);
        List<X509Certificate> chain = Stream.of(chainArray).map(it ->
                (X509Certificate) it).collect(Collectors.toList());

        // Создаем CAdES подпись.
        CAdESSignature cadesSignature = new CAdESSignature(detached);
        cadesSignature.addSigner(JCP.PROVIDER_NAME, null, null, privateKey, chain, TypeCades, tsp, false);
        // Добавление цепочки сертификатов в созданную подпись
        List<X509CertificateHolder> chainHolder = new ArrayList<>();
        for (Certificate s : chainArray) {
            chainHolder.add(new X509CertificateHolder(s.getEncoded()));
        }
        cadesSignature.setCertificateStore(new CollectionStore(chainHolder));

        ByteArrayOutputStream signatureStream = new ByteArrayOutputStream();
        cadesSignature.open(signatureStream); // подготовка контекста
        cadesSignature.update(data); // хеширование
        cadesSignature.close(); // создание подписи с выводом в signatureStream
        signatureStream.close();

        return signatureStream.toByteArray();
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание подписи XAdES_BES")
    @PostMapping(value = "/xades_bes", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> XAdES_BES(@RequestBody byte[] data,
                                       @RequestParam(value = "alias") String alias,
                                       @RequestParam(value = "password") String password,
                                       @RequestParam(value = "ref_acct") String ref_acct) throws Exception {
        return createXAdES(data, alias, password, null, ref_acct, XAdESType.XAdES_BES);
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание подписи XAdES-T")
    @PostMapping(value = "/xades_t", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> XAdES_T(@RequestBody byte[] data,
                                     @RequestParam(value = "alias") String alias,
                                     @RequestParam(value = "password") String password,
                                     @RequestParam(value = "tsp") String tsp,
                                     @RequestParam(value = "ref_acct") String ref_acct) throws Exception {
        return createXAdES(data, alias, password, tsp, ref_acct, XAdESType.XAdES_T);
    }

    private ResponseEntity<?> createXAdES(byte[] data, String alias, String password, String tsp, String ref_acct, Integer TypeXAdES) throws Exception {
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
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_XML)
                .body(signatureStream.toByteArray());
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/pdf")})})
    @Operation(summary = "Создание подписи PAdES")
    @PostMapping(value = "/pades", consumes = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<?> PAdES(@RequestBody byte[] dataPDF,
                                   @RequestParam(value = "alias") String alias,
                                   @RequestParam(value = "password") String password,
                                   @RequestParam(value = "tsp", required = false) String tsp) throws Exception {
        PdfReader reader = new PdfReader(dataPDF);
//
//        z = createCAdES(reader., alias, password, tsp, false, CAdESType.CAdES_T);

        ByteArrayOutputStream signatureStream = new ByteArrayOutputStream();
        PdfStamper stp = PdfStamper.createSignature(reader, signatureStream, '\0');

        PdfSignatureAppearance sap = stp.getSignatureAppearance();

        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());
        Certificate[] chainArray = hdImageStore.getCertificateChain(alias);
        List<X509Certificate> chain = Stream.of(chainArray).map(it ->
                (X509Certificate) it).collect(Collectors.toList());

        sap.setCertificate(chain.get(0));
        sap.setReason("sign");
        sap.setLocation(tsp);
        //sap.setVisibleSignature(new Rectangle(100, 100, 200, 200), 1, null);

        //PdfSignature dic = new PdfSignature(PdfName.ADOBE_CryptoProPDF, PdfName.ADBE_PKCS7_DETACHED);
        PdfSignature dic = new PdfSignature(PdfName.ADOBE_CryptoProPDF, PdfName.ETSI_CADES_DETACHED);
        dic.setReason(sap.getReason());
        dic.setLocation(sap.getLocation());
        dic.setSignatureCreator(sap.getSignatureCreator());
        dic.setContact(sap.getContact());
        dic.setDate(new PdfDate(sap.getSignDate())); // time-stamp will over-rule this
        sap.setCryptoDictionary(dic);
        int estimatedSize = 8192;

        HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
        exc.put(PdfName.CONTENTS, estimatedSize * 2 + 2);
        sap.preClose(exc);

        String pubKeyAlg = chain.get(0).getPublicKey().getAlgorithm();
        String digestOid = AlgorithmUtility.keyAlgToDigestOid(pubKeyAlg);

        MessageDigest md = MessageDigest.getInstance(digestOid);

        String digestAlgorithmName = md.getAlgorithm();

        Certificate[] array = new Certificate[chain.size()];
        chain.toArray(array); // fill the array
        PdfPKCS7 sgn = new PdfPKCS7(privateKey, array, digestAlgorithmName, JCP.PROVIDER_NAME, null, false);

        InputStream data = sap.getRangeStream();
        byte hash[] = DigestAlgorithms.digest(data, md);

        Calendar cal = Calendar.getInstance();

        byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, cal,
                null, null, MakeSignature.CryptoStandard.CMS);

        sgn.update(sh, 0, sh.length);
        byte[] encodedSig = sgn.getEncodedPKCS7(hash, cal);

        if (estimatedSize < encodedSig.length) {
            throw new IOException("Not enough space");
        } // if

        byte[] paddedSig = new byte[estimatedSize];
        System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

        PdfDictionary dic2 = new PdfDictionary();
        dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));

        sap.close(dic2);
        stp.close();
        reader.close();
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .body(signatureStream.toByteArray());
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/pkcs7-signature")})})
    @Operation(summary = "Создание подписи CMS")
    @PostMapping(value = "/cms")
    public byte[] cms(@RequestBody byte[] data,
                      @RequestParam(value = "alias") String alias,
                      @RequestParam(value = "password") String password,
                      @RequestParam(value = "detached") boolean detached) throws Exception {
        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());
        Certificate cert = hdImageStore.getCertificate(alias);

        // Добавление или исключение подписанных атрибутов
        boolean isContentType = false;
        boolean isTime = false;
        boolean isSigningCertificateV2 = false;
        return CMSprocessing.createCMS(privateKey, cert, detached, data, isContentType, isTime, isSigningCertificateV2);
    }
}
