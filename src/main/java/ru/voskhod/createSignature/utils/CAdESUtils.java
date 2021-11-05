package ru.voskhod.createSignature.utils;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.CollectionStore;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.JCP.JCP;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CAdESUtils {

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
}
