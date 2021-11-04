package ru.voskhod;


import ru.CryptoPro.JCP.JCP;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Scanner;

// Список подписей:
// CMS (att.)
// CMS (det.)
// CMS (hash) + hash.txt
// + CAdES-BES
// + CAdES-T
// + CAdES-X-Long-Type 1
// XML-DSig
// + XAdES-BES
// XAdES-T
// XAdES-X-Long-Type 1
// WS_Security
// PAdES (штамп)
// PAdES (без штампа)

public class ShowKeys {
    public static void main(String[] args) throws Exception {
        // Работает следующие строки
        // cd "C:\Program Files\Java\jdk-11.0.13\bin"
        // keytool -importcert -trustcacerts -alias uneproot -keystore "C:\Program Files\Java\jdk-11.0.13\lib\security\cacerts" -file "C:\Users\dimatroickij\IdeaProjects\createCert\src\main\resources\root.cer"
        // Пароль: changeit

        Security.addProvider(new JCP());
        final KeyStore hdImageStore = KeyStore.getInstance(JCP.HD_STORE_NAME, JCP.PROVIDER_NAME);
        hdImageStore.load(null, null);

        Enumeration<String> enumeration = hdImageStore.aliases();
        String rowFormat = "%20s%50s%20s%45s%45s%30s%30s\n";
        System.out.printf(rowFormat, "Common Name", "Alias", "Algorithm", "Serial", "Thumbprint", "NotBefore", "NotAfter");
        List<String> listCert = new ArrayList<>();

        while (enumeration.hasMoreElements()) {
            String s = enumeration.nextElement();
            try {
                X509Certificate certificate = (X509Certificate) hdImageStore.getCertificate(s);
                BigInteger serialNumber = certificate.getSerialNumber();
                String CN = certificate.getSubjectDN().toString().split(",")[0];
                System.out.printf(rowFormat, CN, s, certificate.getPublicKey().getAlgorithm(),
                        serialNumber.toString(16), getThumbprint(certificate),
                        certificate.getNotBefore().toString(),
                        certificate.getNotAfter().toString());
                listCert.add(s);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        //System.out.println("Выберите нужный сертификат");
        //Scanner in = new Scanner(System.in);
        int number = 0;
        //int number = in.nextInt();
        String password = "123456";
        String path = "src/main/resources/";
        Signer signer = new Signer();
        List<String> certChain = new ArrayList<>();

        InputStream is = ShowKeys.class.getClassLoader().getResourceAsStream("file.txt");
        byte[] file = Files.readAllBytes(Paths.get(path + "file.txt"));
        byte[] fileXML = Files.readAllBytes(Paths.get(path + "file.xml"));

        // Не работает !!!
        try (FileOutputStream fos = new FileOutputStream(path + "/output/CMS (att.).sig")) {
            fos.write(signer.CMS(listCert.get(number), password, file, false));
        }

        // Не работает !!!
//        try (FileOutputStream fos = new FileOutputStream(path + "CMS (det.).sig")) {
//            fos.write(signer.CMS(listCert.get(number), password, file, true));
//        }

        // Не работает !!!
//        try (FileOutputStream hash = new FileOutputStream(path + "CMS (det.).hash")) {
////            Base64.toBase64String(Hasher.getHash2012(data))
//            hash.write(Hasher.getHash2012(file));
//        }

//        // Работает
//        try (FileOutputStream fos = new FileOutputStream(path + "/output/CAdES-BES.sig")) {
//            fos.write(signer.CAdES_BES(listCert.get(number), password, file, false));
//        }
//
//        // Работает
//        try (FileOutputStream fos = new FileOutputStream(path + "/output/CAdES-T.sig")) {
//            fos.write(signer.CAdES_T(listCert.get(number), password, file, "http://testca2012.cryptopro.ru/tsp/tsp.srf", false));
//        }
//
//        // Работает
//        try (FileOutputStream fos = new FileOutputStream(path + "/output/CAdES-X Long Type 1.sig")) {
//            fos.write(signer.CAdES_X_LONG_TYPE_1(listCert.get(number), password, file, "http://testca2012.cryptopro.ru/tsp/tsp.srf", false));
//        }
//
//        // XML-DSig
//
//        // Работает
//        try (FileOutputStream fos = new FileOutputStream(path + "/output/XAdES-BES.xml")) {
//            fos.write(signer.XAdES_BES(listCert.get(number), password, fileXML, "acct"));
//        }
//
//        // Работает
//        try (FileOutputStream fos = new FileOutputStream(path + "/output/XAdES-T.xml")) {
//            fos.write(signer.XAdES_T(listCert.get(number), password, fileXML, "http://testca2012.cryptopro.ru/tsp/tsp.srf", "acct"));
//        }
//
//        // WS-Security
//
//        // PAdES
    }

    private static String getThumbprint(X509Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();

        StringBuilder hexStringBuffer = new StringBuilder();
        for (byte b : digest) {
            hexStringBuffer.append(byteToHex(b));
        }
        return hexStringBuffer.toString().toLowerCase();
    }

    public static String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }
}
