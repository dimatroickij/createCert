package ru.voskhod.createSignature.utils;

import org.bouncycastle.util.encoders.Base64;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.tools.AlgorithmUtility;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public class TimeStampUtils {

    static String VerifyTimeStamp = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyTimeStamp>\n" +
            "         <esv:stamp>{%stamp%}</esv:stamp>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyTimeStamp>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    static String VerifyTimeStampWithReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyTimeStampWithReport>\n" +
            "         <esv:stamp>{%stamp%}</esv:stamp>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyTimeStampWithReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    static String VerifyTimeStampWithSignedReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyTimeStampWithSignedReport>\n" +
            "         <esv:stamp>{%stamp%}</esv:stamp>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyTimeStampWithSignedReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    public static byte[] createTimeStamp(String alias, String tsp) throws Exception {
        KeyStore hdImageStore = KeyStore.getInstance(JCP.HD_STORE_NAME, JCP.PROVIDER_NAME);
        hdImageStore.load(null, null);

        Certificate cert = hdImageStore.getCertificate(alias);
        String pubKeyAlg = cert.getPublicKey().getAlgorithm();
        String digestOid = AlgorithmUtility.keyAlgToDigestOid(pubKeyAlg);
        MessageDigest digest = MessageDigest.getInstance(AlgorithmUtility.MAP_REPLACING_DIGEST_ALGORITHMS
                .get(digestOid).toString());
        ru.voskhod.createSignature.utils.TSAClient tsaClient = new ru.voskhod.createSignature.utils.TSAClient(tsp,
                null, null, digest);
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        String data = dateFormat.format(new Date());
        digest.digest(TSAClient.hexStringToByteArray(dateFormat.format(new Date())));
        return tsaClient.getTimeStampToken(data.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] createVerifyTimeStamp(byte[] stamp, boolean verifySignatureOnly) throws Exception {
        return createVerifyTimeStamp(stamp, null, null, verifySignatureOnly, true);
    }

    public static byte[] createVerifyTimeStamp(String alias, String tsp,
                                               boolean verifySignatureOnly) throws Exception {
        return createVerifyTimeStamp(null, alias, tsp, verifySignatureOnly, false);
    }

    static byte[] createVerifyTimeStamp(byte[] data, String alias, String tsp,
                                        boolean verifySignatureOnly, boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createTimeStamp(alias, tsp);
        }
        return VerifyTimeStamp.replace("{%stamp%}", Base64.toBase64String(data))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyTimeStampWithReport(byte[] stamp, boolean verifySignatureOnly) throws Exception {
        return createVerifyTimeStampWithReport(stamp, null, null, verifySignatureOnly, true);
    }

    public static byte[] createVerifyTimeStampWithReport(String alias, String tsp,
                                                         boolean verifySignatureOnly) throws Exception {
        return createVerifyTimeStampWithReport(null, alias, tsp, verifySignatureOnly, false);
    }

    static byte[] createVerifyTimeStampWithReport(byte[] data, String alias, String tsp,
                                                  boolean verifySignatureOnly,
                                                  boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createTimeStamp(alias, tsp);
        }
        return VerifyTimeStampWithReport.replace("{%stamp%}", Base64.toBase64String(data))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyTimeStampWithSignedReport(byte[] stamp,
                                                               boolean verifySignatureOnly) throws Exception {
        return createVerifyTimeStampWithSignedReport(stamp, null, null, verifySignatureOnly, true);
    }

    public static byte[] createVerifyTimeStampWithSignedReport(String alias, String tsp,
                                                               boolean verifySignatureOnly) throws Exception {
        return createVerifyTimeStampWithSignedReport(null, alias, tsp, verifySignatureOnly, false);
    }

    static byte[] createVerifyTimeStampWithSignedReport(byte[] data, String alias, String tsp,
                                                        boolean verifySignatureOnly,
                                                        boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createTimeStamp(alias, tsp);
        }
        return VerifyTimeStampWithSignedReport.replace("{%stamp%}", Base64.toBase64String(data))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }
}
