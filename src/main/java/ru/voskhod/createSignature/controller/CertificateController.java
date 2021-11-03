package ru.voskhod.createSignature.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.CryptoPro.JCP.JCP;
import ru.voskhod.createSignature.dto.CertificateDto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

@RestController
@RequestMapping("/certificate")
@Log
@Tag(name = "Certificate", description = "Работа с сертификатами")
public class CertificateController {
    KeyStore hdImageStore = KeyStore.getInstance(JCP.HD_STORE_NAME, JCP.PROVIDER_NAME);

    public CertificateController() throws KeyStoreException, NoSuchProviderException {
    }

    @Operation(summary = "Список установленных сертификатов")
    @GetMapping("/all")
    public List<CertificateDto> get() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        hdImageStore.load(null, null);
        Enumeration<String> enumeration = hdImageStore.aliases();
        List<CertificateDto> listCert = new ArrayList<>();
        while (enumeration.hasMoreElements()) {
            String s = enumeration.nextElement();
            try {
                X509Certificate certificate = (X509Certificate) hdImageStore.getCertificate(s);
                BigInteger serialNumber = certificate.getSerialNumber();
                String CN = certificate.getSubjectDN().toString().split(",")[0];
                String publicKey = certificate.getPublicKey().getAlgorithm();
                String serial = serialNumber.toString(16);
                CertificateDto certDto = new CertificateDto(CN, s, publicKey, serial, getThumbprint(certificate),
                        new SimpleDateFormat("E MMM d H:m:s z y", Locale.ENGLISH).parse(certificate.getNotBefore().toString()),
                        new SimpleDateFormat("E MMM d H:m:s z y", Locale.ENGLISH).parse(certificate.getNotAfter().toString()));
                listCert.add(certDto);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return listCert;
    }

    @Operation(summary = "Просмотр данных сертификата")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/json",
            schema = @Schema(implementation = CertificateDto.class))})})
    @GetMapping("/{id}")
    public CertificateDto get(@PathVariable String id) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, ParseException {
        hdImageStore.load(null, null);
        X509Certificate certificate = (X509Certificate) hdImageStore.getCertificate(id);
        String CN = certificate.getSubjectDN().toString().split(",")[0];
        String publicKey = certificate.getPublicKey().getAlgorithm();
        BigInteger serialNumber = certificate.getSerialNumber();
        String serial = serialNumber.toString(16);
        return new CertificateDto(CN, id, publicKey, serial, getThumbprint(certificate),
                new SimpleDateFormat("E MMM d H:m:s z y", Locale.ENGLISH).parse(certificate.getNotBefore().toString()),
                new SimpleDateFormat("E MMM d H:m:s z y", Locale.ENGLISH).parse(certificate.getNotAfter().toString()));
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
