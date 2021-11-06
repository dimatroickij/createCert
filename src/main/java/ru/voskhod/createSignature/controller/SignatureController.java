package ru.voskhod.createSignature.controller;

import com.sun.org.apache.xml.internal.security.Init;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.java.Log;
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
    @PostMapping(value = "/cades_bes")
    public byte[] CAdES_BES(@RequestBody byte[] data,
                            @RequestParam(value = "alias") String alias,
                            @RequestParam(value = "password") String password,
                            @RequestParam(value = "detached") boolean detached) throws Exception {
        return CAdESUtils.createCAdES(data, alias, password, null, detached, CAdESType.CAdES_BES);
    }

    @Operation(summary = "Создание подписи CAdES-T")
    @ApiResponses(value = {@ApiResponse(responseCode = "200",
            content = {@Content(mediaType = "application/pkcs7-signature")})})
    @PostMapping(value = "/cades_t")
    public byte[] CAdES_T(@RequestBody byte[] data,
                          @RequestParam(value = "alias") String alias,
                          @RequestParam(value = "password") String password,
                          @RequestParam(value = "tsp") String tsp,
                          @RequestParam(value = "detached") boolean detached) throws Exception {
        return CAdESUtils.createCAdES(data, alias, password, tsp, detached, CAdESType.CAdES_T);
    }

    @Operation(summary = "Создание подписи CAdES-X-Long-Type 1")
    @ApiResponses(value = {@ApiResponse(responseCode = "200",
            content = {@Content(mediaType = "application/pkcs7-signature")})})
    @PostMapping(value = "/cades_x")
    public byte[] CAdES_X(@RequestBody byte[] data,
                          @RequestParam(value = "alias") String alias,
                          @RequestParam(value = "password") String password,
                          @RequestParam(value = "tsp") String tsp,
                          @RequestParam(value = "detached") boolean detached) throws Exception {
        return CAdESUtils.createCAdES(data, alias, password, tsp, detached, CAdESType.CAdES_X_Long_Type_1);
    }

    @Operation(summary = "Создание подписи XML-DSig")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/xmldsig")
    public ResponseEntity<?> XMLDSig(@RequestBody byte[] data,
                                     @RequestParam(value = "alias") String alias,
                                     @RequestParam(value = "password") String password) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(XMLUtils.createXMLDSig(data, alias, password));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание подписи XAdES_BES")
    @PostMapping(value = "/xades_bes", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> XAdES_BES(@RequestBody byte[] data,
                                       @RequestParam(value = "alias") String alias,
                                       @RequestParam(value = "password") String password,
                                       @RequestParam(value = "ref_acct") String ref_acct) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(XAdESUtils.createXAdES(data, alias, password, null, ref_acct, XAdESType.XAdES_BES));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание подписи XAdES-T")
    @PostMapping(value = "/xades_t", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> XAdES_T(@RequestBody byte[] data,
                                     @RequestParam(value = "alias") String alias,
                                     @RequestParam(value = "password") String password,
                                     @RequestParam(value = "tsp") String tsp,
                                     @RequestParam(value = "ref_acct") String ref_acct) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(XAdESUtils.createXAdES(data, alias, password, tsp, ref_acct, XAdESType.XAdES_T));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание подписи WS-Security")
    @PostMapping(value = "/wss", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> wss(@RequestBody byte[] data,
                                 @RequestParam(value = "alias") String alias,
                                 @RequestParam(value = "password") String password) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(WSSecurityUtils.createWSS(data, alias, password));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/pdf")})})
    @Operation(summary = "Создание подписи PAdES")
    @PostMapping(value = "/pades", consumes = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<?> PAdES(@RequestBody byte[] dataPDF,
                                   @RequestParam(value = "alias") String alias,
                                   @RequestParam(value = "password") String password,
                                   @RequestParam(value = "tsp", required = false) String tsp) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_PDF)
                .body(PAdESUtils.createPAdES(dataPDF, alias, password, tsp));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200",
            content = {@Content(mediaType = "application/pkcs7-signature")})})
    @Operation(summary = "Создание подписи CMS")
    @PostMapping(value = "/cms")
    public byte[] cms(@RequestBody byte[] data,
                      @RequestParam(value = "alias") String alias,
                      @RequestParam(value = "password") String password,
                      @RequestParam(value = "detached") boolean detached) throws Exception {

        // Добавление или исключение подписанных атрибутов
        boolean isContentType = false;
        boolean isTime = false;
        boolean isSigningCertificateV2 = false;
        CMSUtils cmsUtils = new CMSUtils(data, alias, password, detached);
        cmsUtils.createCMS(isContentType, isTime, isSigningCertificateV2);
        byte[] signature = cmsUtils.getSignature();
        byte[] digest = cmsUtils.getDigest();
        String hash = cmsUtils.getHash();
        return signature;
    }
}
