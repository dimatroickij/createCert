package ru.voskhod.createSignature.utils;

import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import org.bouncycastle.util.encoders.Base64;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.tools.AlgorithmUtility;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.HashMap;

public class PAdESUtils {

    //TODO: Сделать PAdES-X
    static String VerifyPAdES = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyPAdES>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyPAdES>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    static String VerifyPAdESWithReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyPAdESWithReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyPAdESWithReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    static String VerifyPAdESWithSignedReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyPAdESWithSignedReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyPAdESWithSignedReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    public static byte[] createPAdES(byte[] dataPDF, String alias, String password, String tsp) throws Exception {
        KeyStore hdImageStore = KeyStore.getInstance(JCP.HD_STORE_NAME, JCP.PROVIDER_NAME);
        hdImageStore.load(null, null);
        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());

        PdfReader reader = new PdfReader(dataPDF);
        ByteArrayOutputStream signatureStream = new ByteArrayOutputStream();
        PdfStamper stp = PdfStamper.createSignature(reader, signatureStream, '\0');

        PdfSignatureAppearance sap = stp.getSignatureAppearance();

        Certificate[] chainArray = hdImageStore.getCertificateChain(alias);
        sap.setCertificate(chainArray[0]);

        //sap.setVisibleSignature(new Rectangle(100, 100, 200, 200), 1, null);

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
        String pubKeyAlg = chainArray[0].getPublicKey().getAlgorithm();
        String digestOid = AlgorithmUtility.keyAlgToDigestOid(pubKeyAlg);

        InputStream data = sap.getRangeStream();
        MessageDigest md = MessageDigest.getInstance(digestOid);
        byte hash[] = DigestAlgorithms.digest(data, md);

        String digestAlgorithmName = md.getAlgorithm();

        //CMSUtils cmsUtils = new CMSUtils(hash, alias, password, true, false, false, false);
//        byte[] x = cmsUtils.createCMS(true, true, true);
        byte[] x = CAdESUtils.createCAdES(hash, alias, password, null, true, CAdESType.CAdES_BES);
        PdfPKCS7 sgn = new PdfPKCS7(privateKey, chainArray, digestAlgorithmName, JCP.PROVIDER_NAME,
                new BouncyCastleDigest(), false);

        Calendar cal = Calendar.getInstance();

        byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, cal,
                null, null, MakeSignature.CryptoStandard.CADES);

        sgn.update(sh, 0, sh.length);

        byte[] encodedSig = sgn.getEncodedPKCS7(hash, cal, null, null, null,
                MakeSignature.CryptoStandard.CADES);

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

        return signatureStream.toByteArray();
    }

    public static byte[] createVerifyPAdES(byte[] data, boolean verifySignatureOnly) throws Exception {
        return createVerifyPAdES(data, null, null, null, verifySignatureOnly, true);
    }

    public static byte[] createVerifyPAdES(byte[] data, String alias, String password, String tsp,
                                           boolean verifySignatureOnly) throws Exception {
        return createVerifyPAdES(data, alias, password, tsp, verifySignatureOnly, false);
    }

    static byte[] createVerifyPAdES(byte[] data, String alias, String password, String tsp,
                                    boolean verifySignatureOnly, boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createPAdES(data, alias, password, tsp);
        }
        return VerifyPAdES.replace("{%message%}", Base64.toBase64String(data))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyPAdESWithReport(byte[] data, boolean verifySignatureOnly) throws Exception {
        return createVerifyPAdESWithReport(data, null, null, null,
                verifySignatureOnly, true);
    }

    public static byte[] createVerifyPAdESWithReport(byte[] data, String alias, String password, String tsp,
                                                     boolean verifySignatureOnly) throws Exception {
        return createVerifyPAdESWithReport(data, alias, password, tsp, verifySignatureOnly, false);
    }

    static byte[] createVerifyPAdESWithReport(byte[] data, String alias, String password, String tsp,
                                              boolean verifySignatureOnly,
                                              boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createPAdES(data, alias, password, tsp);
        }
        return VerifyPAdESWithReport.replace("{%message%}", Base64.toBase64String(data))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyPAdESWithSignedReport(byte[] data, boolean verifySignatureOnly) throws Exception {
        return createVerifyPAdESWithSignedReport(data, null, null, null,
                verifySignatureOnly, true);
    }

    public static byte[] createVerifyPAdESWithSignedReport(byte[] data, String alias, String password, String tsp,
                                                           boolean verifySignatureOnly) throws Exception {
        return createVerifyPAdESWithSignedReport(data, alias, password, tsp, verifySignatureOnly, false);
    }

    static byte[] createVerifyPAdESWithSignedReport(byte[] data, String alias, String password, String tsp,
                                                    boolean verifySignatureOnly,
                                                    boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createPAdES(data, alias, password, tsp);
        }
        return VerifyPAdESWithSignedReport.replace("{%message%}", Base64.toBase64String(data))
                .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                .getBytes(StandardCharsets.UTF_8);
    }

}
