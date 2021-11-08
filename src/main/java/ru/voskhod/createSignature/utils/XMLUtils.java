package ru.voskhod.createSignature.utils;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.tools.AlgorithmUtility;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class XMLUtils {

    public static String VerifyXMLSignature = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyXMLSignature>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyXMLSignature>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    public static String VerifyXMLSignatureWithReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyXMLSignatureWithReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyXMLSignatureWithReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    public static String VerifyXMLSignatureWithSignedReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyXMLSignatureWithSignedReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyXMLSignatureWithSignedReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    public static byte[] createXMLDSig(byte[] data, String alias, String password) throws Exception {
        KeyStore hdImageStore = KeyStore.getInstance(JCP.HD_STORE_NAME, JCP.PROVIDER_NAME);
        hdImageStore.load(null, null);
        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());
        X509Certificate certificate = (X509Certificate) hdImageStore.getCertificate(alias);

        String pubKeyAlg = certificate.getPublicKey().getAlgorithm();
        String digestOid = AlgorithmUtility.keyAlgToDigestOid(pubKeyAlg);

        String digestAlgorithm = AlgorithmUtility.MAP_REPLACING_DIGEST_ALGORITHMS.get(digestOid).toString().
                toLowerCase().replace("gost", "gostr").
                replaceFirst("_", "").replace("_", "-");

        String digestMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:" + digestAlgorithm;

        // if (algoOid == "1.2.643.7.1.1.1.1") {   // алгоритм подписи ГОСТ Р 34.10-2012 с ключом 256 бит
        //        signMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";
        //        digestMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
        //    }
        //    else if (algoOid == "1.2.643.7.1.1.1.2") {   // алгоритм подписи ГОСТ Р 34.10-2012 с ключом 512 бит
        //        signMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512";
        //        digestMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512";
        //    }
        //    else if (algoOid == "1.2.643.2.2.19") {  // алгоритм ГОСТ Р 34.10-2001
        //        signMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411";
        //        digestMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411";
        //    }

        String signedAlgorithm = pubKeyAlg.toLowerCase().replace("gost", "gostr").
                replaceFirst("_", "").split("_")[0];
        final String signMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:" +
                signedAlgorithm + "-" + digestAlgorithm;
        // загрузка содержимого подписываемого документа на основе установленных флагами правил
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        final DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
        final Document doc = documentBuilder.parse(new ByteArrayInputStream(data));

        /* Добавление узла подписи <ds:Signature> в загруженный XML-документ */

        // инициализация объекта формирования ЭЦП в соответствии с алгоритмом
        XMLSignature sig = new XMLSignature(doc, "", signMethod);

        // получение корневого узла XML-документа
        final Element anElement = doc.getDocumentElement();

        // добавление в корневой узел XML-документа узла подписи
        anElement.appendChild(sig.getElement());

        /* Определение правил работы с XML-документом и добавление в узел подписи этих правил */

        // создание узла преобразований <ds:Transforms> обрабатываемого XML-документа
        final Transforms transforms = new Transforms(doc);

        // добавление в узел преобразований правил работы с документом
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

        // добавление в узел подписи ссылок (узла <ds:Reference>), определяющих правила работы с
        // XML-документом (обрабатывается текущий документ с заданными в узле <ds:Transforms> правилами
        // и заданным алгоритмом хеширования)
        sig.addDocument("", transforms, digestMethod);

        /* Создание подписи всего содержимого XML-документа на основе закрытого ключа, заданных правил и алгоритмов */

        // создание внутри узла подписи узла <ds:KeyInfo> информации об открытом ключе на основе
        // сертификата
        sig.addKeyInfo(certificate);

        // создание подписи XML-документа
        sig.sign(privateKey);

        /* Сохранение подписанного XML-документа в файл */

        // определение потока, в который осуществляется запись подписанного XML-документа
        ByteArrayOutputStream signatureStream = new ByteArrayOutputStream();

        // инициализация объекта копирования содержимого XML-документа в поток
        final TransformerFactory tf = TransformerFactory.newInstance();

        // создание объекта копирования содержимого XML-документа в поток
        final Transformer trans = tf.newTransformer();

        // копирование содержимого XML-документа в поток
        trans.transform(new DOMSource(doc), new StreamResult(signatureStream));
        signatureStream.close();

        return signatureStream.toByteArray();
    }

    public static byte[] createVerifyXMLSignature(byte[] data, boolean verifySignatureOnly) throws Exception {
        return createVerifyXMLSignature(data, null, null, verifySignatureOnly, true);
    }

    public static byte[] createVerifyXMLSignature(byte[] data, String alias, String password,
                                                  boolean verifySignatureOnly) throws Exception {
        return createVerifyXMLSignature(data, alias, password, verifySignatureOnly, false);
    }

    static byte[] createVerifyXMLSignature(byte[] data, String alias, String password,
                                                  boolean verifySignatureOnly, boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createXMLDSig(data, alias, password);
        }
        return VerifyXMLSignature.replace("{%message%}", Base64.toBase64String(data))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyXMLSignatureWithReport(byte[] data, boolean verifySignatureOnly) throws Exception {
        return createVerifyXMLSignatureWithReport(data, null, null, verifySignatureOnly, true);
    }

    public static byte[] createVerifyXMLSignatureWithReport(byte[] data, String alias, String password,
                                                            boolean verifySignatureOnly) throws Exception {
        return createVerifyXMLSignatureWithReport(data, alias, password, verifySignatureOnly, false);
    }

    static byte[] createVerifyXMLSignatureWithReport(byte[] data, String alias, String password,
                                                            boolean verifySignatureOnly,
                                                            boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createXMLDSig(data, alias, password);
        }
        return VerifyXMLSignatureWithReport.replace("{%message%}", Base64.toBase64String(data))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyXMLSignatureWithSignedReport(byte[] data, boolean
            verifySignatureOnly) throws Exception {
        return createVerifyXMLSignatureWithSignedReport(data, null, null,
                verifySignatureOnly, true);
    }

    public static byte[] createVerifyXMLSignatureWithSignedReport(byte[] data, String alias, String password,
                                                                  boolean verifySignatureOnly) throws Exception {
        return createVerifyXMLSignatureWithSignedReport(data, alias, password, verifySignatureOnly, false);
    }

    static byte[] createVerifyXMLSignatureWithSignedReport(byte[] data, String alias, String password,
                                                                  boolean verifySignatureOnly,
                                                                  boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createXMLDSig(data, alias, password);
        }
        return VerifyXMLSignatureWithSignedReport.replace("{%message%}", Base64.toBase64String(data))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }
}
