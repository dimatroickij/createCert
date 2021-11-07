package ru.voskhod.createSignature.controller;

import com.objsys.asn1j.runtime.Asn1TagMatchFailedException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.java.Log;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.CryptoPro.JCP.JCP;
import ru.voskhod.createSignature.dto.CertificateDto;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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
    public List<CertificateDto> all() throws KeyStoreException, CertificateException, IOException,
            NoSuchAlgorithmException {
        hdImageStore.load(null, null);
        Enumeration<String> enumeration = hdImageStore.aliases();
        List<CertificateDto> listCert = new ArrayList<>();
        while (enumeration.hasMoreElements()) {
            String s = enumeration.nextElement();
            try {
                X509Certificate certificate = (X509Certificate) hdImageStore.getCertificate(s);
                BigInteger serialNumber = certificate.getSerialNumber();
                String CN = certificate.getSubjectDN().toString();
                String publicKey = certificate.getPublicKey().getAlgorithm();
                String serial = serialNumber.toString(16);
                CertificateDto certDto = new CertificateDto(CN, s, publicKey, serial, getThumbprint(certificate),
                        new SimpleDateFormat("E MMM d H:m:s z y", Locale.ENGLISH)
                                .parse(certificate.getNotBefore().toString()),
                        new SimpleDateFormat("E MMM d H:m:s z y", Locale.ENGLISH)
                                .parse(certificate.getNotAfter().toString()));
                listCert.add(certDto);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return listCert;
    }

    @Operation(summary = "Просмотр данных сертификата")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/json",
            schema = @Schema(implementation = CertificateDto.class))}),
            @ApiResponse(responseCode = "400", description = "Контейнер не найден",
                    content = {@Content(mediaType = "text/plain")})})
    @GetMapping("/{id}")
    public ResponseEntity<?> get(@Parameter(description = "Alias контейнера") @PathVariable String id)
            throws Exception {
        hdImageStore.load(null, null);
        X509Certificate certificate = (X509Certificate) hdImageStore.getCertificate(id);
        try {
            String CN = certificate.getSubjectDN().toString().split(",")[0];
            String publicKey = certificate.getPublicKey().getAlgorithm();
            BigInteger serialNumber = certificate.getSerialNumber();
            String serial = serialNumber.toString(16);
            return ResponseEntity.ok().body(new CertificateDto(CN, id, publicKey, serial, getThumbprint(certificate),
                    new SimpleDateFormat("E MMM d H:m:s z y", Locale.ENGLISH)
                            .parse(certificate.getNotBefore().toString()),
                    new SimpleDateFormat("E MMM d H:m:s z y", Locale.ENGLISH)
                            .parse(certificate.getNotAfter().toString())));
        } catch (NullPointerException e) {
            return ResponseEntity.status(400).contentType(MediaType.TEXT_PLAIN).body("Контейнера с таким " +
                    "названием нет в хранилище");
        }
    }

    @Operation(summary = "Загрузка контейнера ЭЦП на сервер", description = "В теле запроса передаётся путь до папки " +
            "с файлами контейнера. После выполнения этой функции необходимо загрузить цепочку сертификатов.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "text/plain")}),
            @ApiResponse(responseCode = "202", description = "Под Linux ещё не написан обработчик",
                    content = {@Content(mediaType = "text/plain")}),
            @ApiResponse(responseCode = "400", description = "Неправильный путь до папки",
                    content = {@Content(mediaType = "text/plain")}),
            @ApiResponse(responseCode = "409", description = "Контейнер уже есть в хранилище",
                    content = {@Content(mediaType = "text/plain")})})
    @PostMapping(value = "/uploadContainer", consumes = "text/plain")
    public @ResponseBody
    ResponseEntity<?> uploadContainer(@RequestBody String path) throws Exception {
        hdImageStore.load(null, null);
        Enumeration<String> enumeration = hdImageStore.aliases();
        Set<String> lastAlias = new HashSet<>();
        while (enumeration.hasMoreElements()) {
            String s = enumeration.nextElement();
            lastAlias.add(s);
        }
        File directory = new File(path);
        List<String> z = List.of(path.split("//"));
        String username = System.getProperty("user.home");
        String system = System.getProperty("os.name");
        if (system.toLowerCase().contains("windows")) {
            Path pathCrypto = Path.of(username + "\\AppData\\Local\\Crypto Pro\\" + Path.of(path).getFileName());
            if (new File(pathCrypto.toString()).mkdir()) {
                if (directory.isDirectory()) {
                    for (File item : Objects.requireNonNull(directory.listFiles())) {
                        Files.copy(item.toPath(), Path.of(pathCrypto.toString() + "\\" +
                                item.toPath().getFileName().toString()), StandardCopyOption.REPLACE_EXISTING);
                    }
                    Set<String> newAlias = new HashSet<>();
                    Enumeration<String> enumeration2 = hdImageStore.aliases();
                    while (enumeration2.hasMoreElements()) {
                        String s = enumeration2.nextElement();
                        newAlias.add(s);
                    }
                    newAlias.removeAll(lastAlias);
                    List<String> alias = new ArrayList<>(newAlias);
                    return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body("Контейнер успешно скопирован. " +
                            "Alias контейнера: " + alias.get(0));
                }
                return ResponseEntity.status(400).contentType(MediaType.TEXT_PLAIN).body("Неправильный путь до папки");
            }
            return ResponseEntity.status(409).contentType(MediaType.TEXT_PLAIN).body("Контейнер уже есть в хранилище");
        }
        return ResponseEntity.status(202).contentType(MediaType.TEXT_PLAIN).body("Под Linux ещё не написан обработчик");
    }

    @Operation(summary = "Загрузка цепочки сертификатов. Запрос выполняется после загрузки контейнера ЭЦП.",
            description = "В теле запроса передаётся файл формата .p7b. Для получения файла такого формата " +
                    "необходимо открыть сертификат, перейти во вкладку 'Состав' -> Копировать в файл -> Далее -> " +
                    "Выбрать пункт .p7b и поставить галку 'Включить по возможности все сертификаты в путь " +
                    "сертификации'-> Сохранить.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "text/plain")}),
            @ApiResponse(responseCode = "400", description = "Нет контейнера с таким названием или файл не является " +
                    "сертификатом",
                    content = {@Content(mediaType = "text/plain")}),
            @ApiResponse(responseCode = "403", description = "Неверный пароль",
                    content = {@Content(mediaType = "text/plain")})})
    @PostMapping(value = "/uploadChain", consumes = "application/x-pkcs7-certificates")
    public @ResponseBody
    ResponseEntity<?> uploadChain(@RequestBody byte[] chain,
                                  @Parameter(description = "Alias контейнера") @RequestParam String alias,
                                  @Parameter(description = "Пароль от контейнера") @RequestParam String password)
            throws Exception {
        hdImageStore.load(null, null);
        try {
            PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(alias, password.toCharArray());
            hdImageStore.setKeyEntry(alias, privateKey, password.toCharArray(),
                    ru.CryptoPro.JCPRequest.CertChainLoader.loadChain(chain));
            return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body("Цепочка сертификатов для " + alias +
                    " успешно установлена");
        } catch (UnrecoverableKeyException e) {
            return ResponseEntity.status(403).contentType(MediaType.TEXT_PLAIN).body("Неверный пароль от контейнера");
        } catch (Asn1TagMatchFailedException e) {
            return ResponseEntity.status(400).
                    contentType(MediaType.TEXT_PLAIN).body("Нет контейнера с таким названием, либо" +
                            " пришли не сетификаты");
        }
    }

    @Operation(summary = "Удаление контейнера из хранилища")
    @PostMapping("/deleteContainerAndChain")
    public @ResponseBody
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "text/plain")}),
            @ApiResponse(responseCode = "400", description = "Контейнера нет в хранилище",
                    content = {@Content(mediaType = "text/plain")})})
    ResponseEntity<?> deleteContainerAndChain(@Parameter(description = "Alias контейнера") @RequestParam String alias)
            throws Exception {
        hdImageStore.load(null, null);
        try {
            hdImageStore.deleteEntry(alias);
        } catch (KeyStoreException e) {
            return ResponseEntity.status(400).contentType(MediaType.TEXT_PLAIN).body("Контейнера " +
                    alias + " нет в хранилище");
        }
        return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body("Контейнер " + alias + " успешно удалён");
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
