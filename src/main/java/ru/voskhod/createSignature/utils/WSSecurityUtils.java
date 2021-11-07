package ru.voskhod.createSignature.utils;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.Merlin;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCPxml.Consts;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

public class WSSecurityUtils {

    static String VerifyWSSSignature = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyWSSSignature>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyWSSSignature>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    static String VerifyWSSSignatureWithReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyWSSSignatureWithReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyWSSSignatureWithReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    static String VerifyWSSSignatureWithSignedReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyWSSSignatureWithSignedReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyWSSSignatureWithSignedReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    // TODO
    public static byte[] createWSS(byte[] data, String alias, String password) throws Exception {
        return data;
        //return sign(alias, password.toCharArray(), data).toString().getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyWSSSignature(byte[] data, boolean verifySignatureOnly) throws Exception {
        return createVerifyWSSSignature(data, null, null, verifySignatureOnly, true);
    }

    public static byte[] createVerifyWSSSignature(byte[] data, String alias, String password,
                                                  boolean verifySignatureOnly) throws Exception {
        return createVerifyWSSSignature(data, alias, password, verifySignatureOnly, false);
    }

    static byte[] createVerifyWSSSignature(byte[] data, String alias, String password,
                                                  boolean verifySignatureOnly, boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createWSS(data, alias, password);
        }
        return VerifyWSSSignature.replace("{%message%}", Base64.toBase64String(data))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyWSSSignatureWithReport(byte[] data, boolean verifySignatureOnly) throws Exception {
        return createVerifyWSSSignatureWithReport(data, null, null, verifySignatureOnly, true);
    }

    public static byte[] createVerifyWSSSignatureWithReport(byte[] data, String alias, String password,
                                                            boolean verifySignatureOnly) throws Exception {
        return createVerifyWSSSignatureWithReport(data, alias, password, verifySignatureOnly, false);
    }

    static byte[] createVerifyWSSSignatureWithReport(byte[] data, String alias, String password,
                                                            boolean verifySignatureOnly,
                                                            boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createWSS(data, alias, password);
        }
        return VerifyWSSSignatureWithReport.replace("{%message%}", Base64.toBase64String(data))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyWSSSignatureWithSignedReport(byte[] data,
                                                                  boolean verifySignatureOnly) throws Exception {
        return createVerifyWSSSignatureWithSignedReport(data, null, null,
                verifySignatureOnly, true);
    }

    public static byte[] createVerifyWSSSignatureWithSignedReport(byte[] data, String alias, String password,
                                                                  boolean verifySignatureOnly) throws Exception {
        return createVerifyWSSSignatureWithSignedReport(data, alias, password, verifySignatureOnly, false);
    }

    static byte[] createVerifyWSSSignatureWithSignedReport(byte[] data, String alias, String password,
                                                                  boolean verifySignatureOnly,
                                                                  boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createWSS(data, alias, password);
        }
        return VerifyWSSSignatureWithSignedReport.replace("{%message%}", Base64.toBase64String(data))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }

    public static Document sign(String alias, char[] password,
                                byte[] inDoc) throws Exception {


        WSSConfig.setAddJceProviders(false);
        WSSConfig config = new WSSConfig();
        config.setWsiBSPCompliant(false);

        Merlin merlin = new Merlin();

        // Контейнер пользователя.
        KeyStore keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME, JCP.PROVIDER_NAME);
        keyStore.load(null, null);

        // Хранилище доверенных сертификатов, содержит корневой сертификат клиента.
        KeyStore trustStore = KeyStore.getInstance(JCP.CERT_STORE_NAME, JCP.PROVIDER_NAME);
        trustStore.load(new FileInputStream("C:\\certstore"), "12345678".toCharArray());

        merlin.setKeyStore(keyStore);
        merlin.setTrustStore(trustStore);

        Crypto keyLoader = null;
        keyLoader = merlin;

        // *** Подпись документа ***

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.setMustUnderstand(true);
        secHeader.setActor("acct");

        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        final DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
        final Document doc = documentBuilder.parse(new ByteArrayInputStream(inDoc));
        secHeader.insertSecurityHeader(doc);

        WSSecSignature sigAsymBuilder = new WSSecSignature();
        sigAsymBuilder.setWsConfig(config);
        sigAsymBuilder.setUserInfo(alias, password==null? null:String.valueOf(password));
        sigAsymBuilder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        sigAsymBuilder.setSignatureAlgorithm(Consts.URI_GOST_SIGN);
        sigAsymBuilder.setDigestAlgo(Consts.URI_GOST_DIGEST);

        return sigAsymBuilder.build(doc, keyLoader, secHeader);
    }
}
