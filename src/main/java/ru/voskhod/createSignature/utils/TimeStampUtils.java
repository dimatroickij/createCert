package ru.voskhod.createSignature.utils;

import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;

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


    // TODO
    public static byte[] createTimeStamp(byte[] data, String alias, String password, String tsp) throws Exception {
        return null;
    }

    public static byte[] createVerifyTimeStamp(byte[] stamp, boolean verifySignatureOnly) throws Exception {
        return createVerifyTimeStamp(stamp, null, null, null, verifySignatureOnly, true);
    }

    public static byte[] createVerifyTimeStamp(byte[] data, String alias, String password, String tsp,
                                               boolean verifySignatureOnly) throws Exception {
        return createVerifyTimeStamp(data, alias, password, tsp, verifySignatureOnly, false);
    }

    static byte[] createVerifyTimeStamp(byte[] data, String alias, String password, String tsp,
                                               boolean verifySignatureOnly, boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createTimeStamp(data, alias, password, tsp);
        }
        return VerifyTimeStamp.replace("{%stamp%}", Base64.toBase64String(data))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyTimeStampWithReport(byte[] stamp, boolean verifySignatureOnly) throws Exception {
        return createVerifyTimeStampWithReport(stamp, null, null, null,
                verifySignatureOnly, true);
    }

    public static byte[] createVerifyTimeStampWithReport(byte[] data, String alias, String password, String tsp,
                                                         boolean verifySignatureOnly) throws Exception {
        return createVerifyTimeStampWithReport(data, alias, password, tsp, verifySignatureOnly, false);
    }

    static byte[] createVerifyTimeStampWithReport(byte[] data, String alias, String password, String tsp,
                                                         boolean verifySignatureOnly,
                                                         boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createTimeStamp(data, alias, password, tsp);
        }
        return VerifyTimeStampWithReport.replace("{%stamp%}", Base64.toBase64String(data))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyTimeStampWithSignedReport(byte[] stamp,
                                                               boolean verifySignatureOnly) throws Exception {
        return createVerifyTimeStampWithSignedReport(stamp, null, null, null,
                verifySignatureOnly, true);
    }

    public static byte[] createVerifyTimeStampWithSignedReport(byte[] data, String alias, String password, String tsp,
                                                               boolean verifySignatureOnly) throws Exception {
        return createVerifyTimeStampWithSignedReport(data, alias, password, tsp, verifySignatureOnly, false);
    }

    static byte[] createVerifyTimeStampWithSignedReport(byte[] data, String alias, String password, String tsp,
                                                               boolean verifySignatureOnly,
                                                               boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createTimeStamp(data, alias, password, tsp);
        }
        return VerifyTimeStampWithSignedReport.replace("{%stamp%}", Base64.toBase64String(data))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }
}
