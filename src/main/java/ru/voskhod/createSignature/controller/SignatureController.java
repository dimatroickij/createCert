package ru.voskhod.createSignature.controller;

import com.sun.org.apache.xml.internal.security.Init;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.java.Log;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.CollectionStore;
import org.springframework.web.bind.annotation.*;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;
import ru.CryptoPro.reprov.RevCheck;

import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@RequestMapping("/signature")
@Log
@Tag(name = "Signature", description = "Работа с подписями")
public class SignatureController {
    KeyStore hdImageStore = KeyStore.getInstance(JCP.HD_STORE_NAME, JCP.PROVIDER_NAME);

    public SignatureController() throws KeyStoreException, NoSuchProviderException {
        JCPXMLDSigInit.init();  //без него XAdES не создаётся
        System.setProperty("com.sun.security.enableCRLDP", "true");
        System.setProperty("com.ibm.security.enableCRLDP", "true");
        System.setProperty("ocsp.enable", "true");
        System.setProperty("org.apache.xml.security.resource.config", "resource/jcp.xml");
        Security.addProvider(new JCP());
        Security.addProvider(new RevCheck());
        Init.init();
    }

    @Operation(summary = "Создание подписи CAdES-BES")
    @PostMapping(value = "/cades_bes")
    public byte[] CAdES_BES(@RequestBody byte[] data,
                            @RequestParam(value = "alias", required = false) String alias,
                            @RequestParam(value = "password", required = false) String password) throws Exception {
        hdImageStore.load(null, null);
        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());

        Certificate[] chainArray = hdImageStore.getCertificateChain(alias);
        List<X509Certificate> chain = Stream.of(chainArray).map(it ->
                (X509Certificate) it).collect(Collectors.toList());

        // Создаем CAdES подпись.
        CAdESSignature cadesSignature = new CAdESSignature(false);


        cadesSignature.addSigner(JCP.PROVIDER_NAME, null, null, privateKey, chain, CAdESType.CAdES_BES,
                null, false);

        // Добавление цепочки сертификатов в созданную подпись
        List<X509CertificateHolder> chainHolder = new ArrayList<>();
        chainHolder.add(new X509CertificateHolder(hdImageStore.getCertificate(alias).getEncoded()));
        for (Certificate s : chainArray) {
            chainHolder.add(new X509CertificateHolder(s.getEncoded()));
        }
        CollectionStore collectionStore = new CollectionStore(chainHolder);
        cadesSignature.setCertificateStore(collectionStore);


        //Будущая подпись в виде массива.
        ByteArrayOutputStream signatureStream = new ByteArrayOutputStream();
        cadesSignature.open(signatureStream); // подготовка контекста
        cadesSignature.update(data); // хеширование
        cadesSignature.close(); // создание подписи с выводом в signatureStream
        signatureStream.close();

        return signatureStream.toByteArray();
    }

    @Operation(summary = "Создание подписи CAdES-T")
    @PostMapping(value = "/cades_t")
    public byte[] CAdES_T(@RequestBody byte[] data,
                          @RequestParam(value = "alias", required = false) String alias,
                          @RequestParam(value = "password", required = false) String password,
                          @RequestParam(value = "tsp", required = false) String tsp) throws Exception {

        hdImageStore.load(null, null);
        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());

        X509Certificate cert = (X509Certificate) hdImageStore.getCertificate(alias);

        Certificate[] chainArray = hdImageStore.getCertificateChain(alias);
        List<X509Certificate> chain = Stream.of(chainArray).map(it ->
                (X509Certificate) it).collect(Collectors.toList());

        // Создаем CAdES подпись.
        CAdESSignature cadesSignature = new CAdESSignature(false);

        cadesSignature.addSigner(JCP.PROVIDER_NAME, null, null, privateKey, chain, CAdESType.CAdES_T, tsp,
                false);

        // Добавление цепочки сертификатов в созданную подпись
        List<X509CertificateHolder> chainHolder = new ArrayList<>();
        for (Certificate s : chain) {
            chainHolder.add(new X509CertificateHolder(s.getEncoded()));
        }
        cadesSignature.setCertificateStore(new CollectionStore(chainHolder));

        //Будущая подпись в виде массива.
        ByteArrayOutputStream signatureStream = new ByteArrayOutputStream();
        cadesSignature.open(signatureStream); // подготовка контекста
        cadesSignature.update(data); // хеширование
        cadesSignature.close(); // создание подписи с выводом в signatureStream
        signatureStream.close();

        return signatureStream.toByteArray();
    }

    @Operation(summary = "Создание подписи CAdES-X-Long-Type 1")
    @PostMapping(value = "/cades_x")
    public byte[] CAdES_X(@RequestBody byte[] data,
                          @RequestParam(value = "alias", required = false) String alias,
                          @RequestParam(value = "password", required = false) String password,
                          @RequestParam(value = "tsp", required = false) String tsp) throws Exception {
        hdImageStore.load(null, null);
        PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());

        Certificate[] chainArray = hdImageStore.getCertificateChain(alias);
        List<X509Certificate> chain = Stream.of(chainArray).map(it ->
                (X509Certificate) it).collect(Collectors.toList());

        // Создаем CAdES-X Long Type 1 подпись.
        CAdESSignature cadesSignature = new CAdESSignature(false);
        cadesSignature.addSigner(JCP.PROVIDER_NAME, null, null, privateKey, chain, CAdESType.CAdES_X_Long_Type_1,
                tsp, false);

        // Добавление цепочки сертификатов в созданную подпись
        List<X509CertificateHolder> chainHolder = new ArrayList<>();
        chainHolder.add(new X509CertificateHolder(hdImageStore.getCertificate(alias).getEncoded()));
        for (Certificate s : chainArray) {
            chainHolder.add(new X509CertificateHolder(s.getEncoded()));
        }
        CollectionStore collectionStore = new CollectionStore(chainHolder);
        cadesSignature.setCertificateStore(collectionStore);

        //Будущая подпись в виде массива.
        ByteArrayOutputStream signatureStream = new ByteArrayOutputStream();
        cadesSignature.open(signatureStream); // подготовка контекста
        cadesSignature.update(data); // хеширование
        cadesSignature.close(); // создание подписи с выводом в signatureStream
        signatureStream.close();

        return signatureStream.toByteArray();
    }
}
