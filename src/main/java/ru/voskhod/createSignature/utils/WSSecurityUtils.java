package ru.voskhod.createSignature.utils;

import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;

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
}
