package ru.voskhod.createSignature.controller;

import com.sun.org.apache.xml.internal.security.Init;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.java.Log;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;
import ru.CryptoPro.XAdES.XAdESType;
import ru.CryptoPro.reprov.RevCheck;
import ru.voskhod.createSignature.utils.*;

import java.security.*;

@RestController
@RequestMapping("/signature")
@Log
@Tag(name = "Signature", description = "Работа с подписями")
public class SignatureController {

    public SignatureController() {
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
    @ApiResponses(value = {@ApiResponse(responseCode = "200",
            content = {@Content(mediaType = "application/pkcs7-signature")})})
    @PostMapping(value = "/CAdES_BES")
    public byte[] CAdES_BES(@RequestBody byte[] data,
                            @Parameter(description = "Alias контейнера") @RequestParam String alias,
                            @Parameter(description = "Пароль от контейнера") @RequestParam String password,
                            @Parameter(description = "Тип подписи: отсоединённая (true) или присоединённая (false)")
                            @RequestParam boolean isDetached) throws Exception {
        return CAdESUtils.createCAdES(data, alias, password, null, isDetached, CAdESType.CAdES_BES);
    }

    @Operation(summary = "Создание подписи CAdES-T")
    @ApiResponses(value = {@ApiResponse(responseCode = "200",
            content = {@Content(mediaType = "application/pkcs7-signature")})})
    @PostMapping(value = "/CAdES_T")
    public byte[] CAdES_T(@RequestBody byte[] data,
                          @Parameter(description = "Alias контейнера") @RequestParam String alias,
                          @Parameter(description = "Пароль от контейнера") @RequestParam String password,
                          @Parameter(description = "Адрес TSP сервера") @RequestParam String tsp,
                          @Parameter(description = "Тип подписи: отсоединённая (true) или присоединённая (false)")
                          @RequestParam boolean detached) throws Exception {
        return CAdESUtils.createCAdES(data, alias, password, tsp, detached, CAdESType.CAdES_T);
    }

    @Operation(summary = "Создание подписи CAdES-X-Long-Type 1")
    @ApiResponses(value = {@ApiResponse(responseCode = "200",
            content = {@Content(mediaType = "application/pkcs7-signature")})})
    @PostMapping(value = "/CAdES_X")
    public byte[] CAdES_X(@RequestBody byte[] data,
                          @Parameter(description = "Alias контейнера") @RequestParam String alias,
                          @Parameter(description = "Пароль от контейнера") @RequestParam String password,
                          @Parameter(description = "Адрес TSP сервера") @RequestParam String tsp,
                          @Parameter(description = "Тип подписи: отсоединённая (true) или присоединённая (false)")
                          @RequestParam boolean detached) throws Exception {
        return CAdESUtils.createCAdES(data, alias, password, tsp, detached, CAdESType.CAdES_X_Long_Type_1);
    }

    @Operation(summary = "Создание подписи XML-DSig")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/XMLDSig", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> XMLDSig(@RequestBody byte[] data,
                                     @Parameter(description = "Alias контейнера") @RequestParam String alias,
                                     @Parameter(description = "Пароль от контейнера") @RequestParam String password)
            throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(XMLUtils.createXMLDSig(data, alias, password));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание подписи XAdES_BES")
    @PostMapping(value = "/XAdES_BES", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> XAdES_BES(@RequestBody byte[] data,
                                       @Parameter(description = "Alias контейнера") @RequestParam String alias,
                                       @Parameter(description = "Пароль от контейнера") @RequestParam String password,
                                       @Parameter(description = "ID подписываемого элемента")
                                       @RequestParam String ref_acct) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(XAdESUtils.createXAdES(data, alias, password, null, ref_acct, XAdESType.XAdES_BES));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание подписи XAdES-T")
    @PostMapping(value = "/XAdES_T", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> XAdES_T(@RequestBody byte[] data,
                                     @Parameter(description = "Alias контейнера") @RequestParam String alias,
                                     @Parameter(description = "Пароль от контейнера") @RequestParam String password,
                                     @Parameter(description = "Адрес TSP сервера") @RequestParam String tsp,
                                     @Parameter(description = "ID подписываемого элемента")
                                     @RequestParam String ref_acct) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(XAdESUtils.createXAdES(data, alias, password, tsp, ref_acct, XAdESType.XAdES_T));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание подписи WS-Security")
    @PostMapping(value = "/WSSecurity", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> WSSecurity(@RequestBody byte[] data,
                                        @Parameter(description = "Alias контейнера") @RequestParam String alias,
                                        @Parameter(description = "Пароль от контейнера") @RequestParam String password)
            throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(WSSecurityUtils.createWSS(data, alias, password));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/pdf")})})
    @Operation(summary = "Создание подписи PAdES")
    @PostMapping(value = "/PAdES", consumes = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<?> PAdES(@RequestBody byte[] dataPDF,
                                   @Parameter(description = "Alias контейнера") @RequestParam String alias,
                                   @Parameter(description = "Пароль от контейнера") @RequestParam String password,
                                   @Parameter(description = "Адрес TSP сервера") @RequestParam String tsp)
            throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_PDF)
                .body(PAdESUtils.createPAdES(dataPDF, alias, password, tsp));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", headers = {@Header(name = "Hash-Data",
            description = "Хеш документа (необходим для проверки отсоединённой подписи на портале ГУЦа)")},
            content = {@Content(mediaType = "application/pkcs7-signature")})})
    @Operation(summary = "Создание подписи CMS")
    @PostMapping(value = "/CMS")
    public ResponseEntity<?> CMS(@RequestBody byte[] data,
                                 @Parameter(description = "Alias контейнера") @RequestParam String alias,
                                 @Parameter(description = "Пароль от контейнера") @RequestParam String password,
                                 @Parameter(description = "Тип подписи: отсоединённая (true) или " +
                                         "присоединённая (false)") @RequestParam boolean detached) throws Exception {

        // Добавление или исключение подписанных атрибутов
        boolean isContentType = false;
        boolean isTime = false;
        boolean isSigningCertificateV2 = false;
        CMSUtils cmsUtils = new CMSUtils(data, alias, password, detached, isContentType, isTime,
                isSigningCertificateV2);
        byte[] signature = cmsUtils.getSignature();
        byte[] digest = cmsUtils.getDigest();
        String hash = cmsUtils.getHash();
        return ResponseEntity.status(HttpStatus.OK).header("Hash-Data", hash).body(signature);
    }
}
