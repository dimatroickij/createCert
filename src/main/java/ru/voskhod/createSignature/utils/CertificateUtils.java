package ru.voskhod.createSignature.utils;

import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;

public class CertificateUtils {

    static String VerifyCertificate = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyCertificate>\n" +
            "         <esv:certificate>{%message%}</esv:certificate>\n" +
            "      </esv:VerifyCertificate>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    static String VerifyCertificateWithReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyCertificateWithReport>\n" +
            "         <esv:certificate>{%message%}</esv:certificate>\n" +
            "      </esv:VerifyCertificateWithReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    static String VerifyCertificateWithSignedReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyCertificateWithSignedReport>\n" +
            "         <esv:certificate>{%message%}</esv:certificate>\n" +
            "      </esv:VerifyCertificateWithSignedReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    public static byte[] createVerifyCertificate(byte[] data) {
        return VerifyCertificate.replace("{%message%}",
                Base64.toBase64String(data)).getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyCertificateWithReport(byte[] data) {
        return VerifyCertificateWithReport.replace("{%message%}",
                Base64.toBase64String(data)).getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyCertificateWithSignedReport(byte[] data) {
        return VerifyCertificateWithSignedReport.replace("{%message%}",
                Base64.toBase64String(data)).getBytes(StandardCharsets.UTF_8);
    }
}
