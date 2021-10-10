package ru.voskhod;

import org.apache.xml.utils.XML11Char;
import org.bouncycastle.util.encoders.Base64;
import ru.CryptoPro.JCP.JCP;

import javax.xml.bind.DatatypeConverter;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class ShowKeys {
    public static void main(String[] args) throws Exception {
        // C:\jcp-2.0.40035 ControlPane.bat "C:\Program Files\Java\jre1.8.0_301\"

        // C:\Program Files\Java\jre1.8.0_301\bin>keytool -importcert -trustcacerts -alias uneproot -keystore "C:\Program Files\Java\jre1.8.0_301\lib\security\cacerts" -file "C:\Users\dimatroickij\Downloads\root.cer"
        // C:\Program Files\Java\jre1.8.0_301\bin>keytool -importcert -trustcacerts -alias uneproot -keystore "C:\Program Files\Java\jdk1.8.0_301\jre\lib\security\cacerts" -file "C:\Users\dimatroickij\Downloads\root.cer"
        //C:\Program Files\Java\jre1.8.0_301\bin> keytool -keystore C:\Program Files\Java\jre1.8.0_301\lib\security/cacerts -importcert -alias mainroot -file ./root.cer
        Security.addProvider(new JCP());
        final KeyStore hdImageStore = KeyStore.getInstance(JCP.HD_STORE_NAME, JCP.PROVIDER_NAME);
        hdImageStore.load(null, null);

        Enumeration<String> enumeration = hdImageStore.aliases();
        String rowFormat = "%50s%20s%45s%45s%30s%30s\n";
        System.out.printf(rowFormat, "alias", "SigAlg", "serial", "Thumbprint", "NotAfter", "NotBefore");
        List<String> listCert = new ArrayList<>();

        while (enumeration.hasMoreElements()) {
            String s = enumeration.nextElement();
            try {
                X509Certificate certificate = (X509Certificate) hdImageStore.getCertificate(s);
                BigInteger serialNumber = certificate.getSerialNumber();
                System.out.printf(rowFormat, s, certificate.getPublicKey().getAlgorithm(),
                        serialNumber.toString(16), getThumbprint(certificate),
                        certificate.getNotAfter().toString(),
                        certificate.getNotBefore().toString());
                listCert.add(s);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        //System.out.println("Выберите нужный сертификат");
        //Scanner in = new Scanner(System.in);
        int number = 2;//in.nextInt();
        String password = "123456";
        Signer signer = new Signer();
        List<String> certChain = new ArrayList<>();

        byte[] file = Files.readAllBytes(Paths.get("C:\\Users\\dimatroickij\\Desktop\\test.txt"));
        byte[] fileXML = Files.readAllBytes(Paths.get("C:\\Users\\dimatroickij\\Desktop\\test.xml"));

        // Работает
//        try (FileOutputStream fos = new FileOutputStream("C:\\Users\\dimatroickij\\Desktop\\CMS (att.).sig")) {
//            fos.write(signer.CMS(listCert.get(number - 1), password, file, false));
//        }

        // Работает
        try (FileOutputStream fos = new FileOutputStream("C:\\Users\\dimatroickij\\Desktop\\CMS (det.).sig")) {
            fos.write(signer.CMS(listCert.get(number - 1), password, file, true));
            System.out.println(Base64.toBase64String(Hasher.getHash2012(file)));
        }

        try (FileOutputStream hash = new FileOutputStream("C:\\Users\\dimatroickij\\Desktop\\CMS (det.).hash")) {
//          Base64.toBase64String(Hasher.getHash2012(data))
            hash.write(Hasher.getHash2012(file));
        }

        // !!! НЕ РАБОТАЕТ !!!
        try (FileOutputStream fos = new FileOutputStream("C:\\Users\\dimatroickij\\Desktop\\CAdES-BES.sig")) {
            fos.write(signer.CAdES_BES(listCert.get(number - 1), password, file, false));
        }

        // Работает
        try (FileOutputStream fos = new FileOutputStream("C:\\Users\\dimatroickij\\Desktop\\CAdES-T.sig")) {
            fos.write(signer.CAdES_T(listCert.get(number - 1), password, file, "http://testca2012.cryptopro.ru/tsp/tsp.srf",false));
        }

        // Работает
        try (FileOutputStream fos = new FileOutputStream("C:\\Users\\dimatroickij\\Desktop\\CAdES-X Long Type 1.sig")) {
            fos.write(signer.CAdES_X_LONG_TYPE_1(listCert.get(number - 1), password, file, "http://testca2012.cryptopro.ru/tsp/tsp.srf",false));
        }

//        try (FileOutputStream fos = new FileOutputStream("C:\\Users\\dimatroickij\\Desktop\\XAdES-BES.xml")) {
//            fos.write(signer.XAdES_BES(listCert.get(number - 1), password, fileXML, "nodeID"));
//        }
    }

    private static String getThumbprint(X509Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        String digestHex = DatatypeConverter.printHexBinary(digest);
        return digestHex.toLowerCase();
    }
}
