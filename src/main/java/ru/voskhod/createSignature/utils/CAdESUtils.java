package ru.voskhod.createSignature.utils;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Base64;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.JCP.JCP;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CAdESUtils {

    static String VerifyCAdES = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyCAdES>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyCAdES>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    static String VerifyCAdESWithReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyCAdESWithReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyCAdESWithReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    static String VerifyCAdESWithSignedReport = "<soapenv:Envelope " +
            "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:esv=\"http://esv.server.rt.ru\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <esv:VerifyCAdESWithSignedReport>\n" +
            "         <esv:message>{%message%}</esv:message>\n" +
            "         <esv:verifySignatureOnly>{%verifySignatureOnly%}</esv:verifySignatureOnly>\n" +
            "      </esv:VerifyCAdESWithSignedReport>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

    public static byte[] createCAdES(byte[] data, String alias, String password, String tsp, boolean detached,
                                     Integer TypeCades) throws Exception {
        KeyStore hdImageStore = KeyStore.getInstance(JCP.HD_STORE_NAME, JCP.PROVIDER_NAME);
        hdImageStore.load(null, null);
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

    public static byte[] createVerifyCAdES(byte[] data, Integer typeCAdES, boolean verifySignatureOnly)
            throws Exception {
        return createVerifyCAdES(data, null, null, null, false, typeCAdES,
                verifySignatureOnly, true);
    }

    public static byte[] createVerifyCAdES(byte[] data, String alias, String password, String tsp, boolean detached,
                                           Integer TypeCades, boolean verifySignatureOnly) throws Exception {
        return createVerifyCAdES(data, alias, password, tsp, detached, TypeCades, verifySignatureOnly, false);
    }

    static byte[] createVerifyCAdES(byte[] data, String alias, String password, String tsp, boolean detached,
                                    Integer TypeCades, boolean verifySignatureOnly,
                                    boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createCAdES(data, alias, password, tsp, detached, TypeCades);
        }
        if (Objects.equals(TypeCades, CAdESType.CAdES_X_Long_Type_1))
            return VerifyCAdES.replace("{%message%}", Base64.toBase64String(data))
                    .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                    .getBytes(StandardCharsets.UTF_8);
        else
            return CMSUtils.VerifyCMSSignature.replace("{%message%}", Base64.toBase64String(data))
                    .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                    .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyCAdESWithReport(byte[] data, Integer typeCAdES, boolean verifySignatureOnly)
            throws Exception {
        return createVerifyCAdESWithReport(data, null, null, null, false, typeCAdES,
                verifySignatureOnly, true);
    }

    public static byte[] createVerifyCAdESWithReport(byte[] data, String alias, String password, String tsp,
                                                     boolean detached, Integer TypeCades,
                                                     boolean verifySignatureOnly) throws Exception {
        return createVerifyCAdESWithReport(data, alias, password, tsp, detached, TypeCades,
                verifySignatureOnly, false);
    }

    static byte[] createVerifyCAdESWithReport(byte[] data, String alias, String password, String tsp,
                                              boolean detached, Integer TypeCades, boolean verifySignatureOnly,
                                              boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createCAdES(data, alias, password, tsp, detached, TypeCades);
        }
        if (Objects.equals(TypeCades, CAdESType.CAdES_X_Long_Type_1))
            return VerifyCAdESWithReport.replace("{%message%}", Base64.toBase64String(data))
                    .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                    .getBytes(StandardCharsets.UTF_8);
        else
            return CMSUtils.VerifyCMSSignatureWithReport.replace("{%message%}", Base64.toBase64String(data))
                    .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                    .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] createVerifyCAdESWithSignedReport(byte[] data, Integer typeCAdES, boolean verifySignatureOnly)
            throws Exception {
        return createVerifyCAdESWithSignedReport(data, null, null, null, false,
                typeCAdES, verifySignatureOnly, true);
    }

    public static byte[] createVerifyCAdESWithSignedReport(byte[] data, String alias, String password, String tsp,
                                                           boolean detached, Integer TypeCades,
                                                           boolean verifySignatureOnly) throws Exception {
        return createVerifyCAdESWithSignedReport(data, alias, password, tsp, detached, TypeCades,
                verifySignatureOnly, false);
    }

    static byte[] createVerifyCAdESWithSignedReport(byte[] data, String alias, String password, String tsp,
                                                    boolean detached, Integer TypeCades,
                                                    boolean verifySignatureOnly,
                                                    boolean isSignature) throws Exception {
        if (!isSignature) {
            data = createCAdES(data, alias, password, tsp, detached, TypeCades);
        }
        if (Objects.equals(TypeCades, CAdESType.CAdES_X_Long_Type_1))
            return VerifyCAdESWithSignedReport.replace("{%message%}", Base64.toBase64String(data))
                    .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                    .getBytes(StandardCharsets.UTF_8);
        else
            return CMSUtils.VerifyCMSSignatureWithSignedReport.replace("{%message%}", Base64.toBase64String(data))
                    .replace("{%verifySignatureOnly%}", String.valueOf(verifySignatureOnly))
                    .getBytes(StandardCharsets.UTF_8);
    }
}
