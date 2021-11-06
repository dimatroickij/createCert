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

import java.security.Security;

@RestController
@RequestMapping("/soap")
@Log
@Tag(name = "SOAP", description = "Получение XML файлов для SOAP UI")
public class SOAPController {
    public SOAPController() {
        JCPXMLDSigInit.init();  //без него XAdES не создаётся
        System.setProperty("com.sun.security.enableCRLDP", "true");
        System.setProperty("com.ibm.security.enableCRLDP", "true");
        System.setProperty("ocsp.enable", "true");
        System.setProperty("org.apache.xml.security.resource.config", "resource/jcp.xml");
        Security.addProvider(new JCP());
        Security.addProvider(new RevCheck());
        Init.init();
    }

    @Operation(summary = "Создание запроса на проверку сертификата")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/certificate")
    public ResponseEntity<?> Certificate(@RequestBody byte[] data) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(CertificateUtils.createVerifyCertificate(data));
    }

    @Operation(summary = "Создание запроса на проверку сертификата с отчётом")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/certificateWithReport")
    public ResponseEntity<?> CertificateWithReport(@RequestBody byte[] data) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(CertificateUtils.createVerifyCertificateWithReport(data));
    }

    @Operation(summary = "Создание запроса на проверку сертификата с подписанным отчётом")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/certificateWithSignedReport")
    public ResponseEntity<?> CertificateWithSignedReport(@RequestBody byte[] data) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(CertificateUtils.createVerifyCertificateWithSignedReport(data));
    }

    @Operation(summary = "Создание запроса на проверку CAdES-BES (проверяется как cms)")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/CAdES_BES")
    public ResponseEntity<?> CAdES_BES(@RequestBody byte[] data,
                                       @RequestParam(value = "alias") String alias,
                                       @RequestParam(value = "password") String password,
                                       @RequestParam(value = "isVerifySignatureOnly") boolean isVerifySignatureOnly)
            throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML).body(CAdESUtils.createVerifyCAdES(data,
                alias, password, null, false, CAdESType.CAdES_BES, isVerifySignatureOnly));
    }

    @Operation(summary = "Создание запроса на проверку CAdES-BES с отчётом (проверяется как cms)")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/CAdES_BES_WithReport")
    public ResponseEntity<?> CAdES_BES_WithReport(@RequestBody byte[] data,
                                                  @RequestParam(value = "alias") String alias,
                                                  @RequestParam(value = "password") String password,
                                                  @RequestParam(value = "isVerifySignatureOnly")
                                                          boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(CAdESUtils.createVerifyCAdESWithReport(data, alias, password, null, false,
                        CAdESType.CAdES_BES, isVerifySignatureOnly));
    }

    @Operation(summary = "Создание запроса на проверку CAdES-BES с подписанным отчетом (проверяется как cms)")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/CAdES_BES_WithSignedReport")
    public ResponseEntity<?> CAdES_BES_WithSignedReport(@RequestBody byte[] data,
                                                        @RequestParam(value = "alias") String alias,
                                                        @RequestParam(value = "password") String password,
                                                        @RequestParam(value = "isVerifySignatureOnly")
                                                                boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(CAdESUtils.createVerifyCAdESWithSignedReport(data, alias, password, null, false,
                        CAdESType.CAdES_BES, isVerifySignatureOnly));
    }

    @Operation(summary = "Создание запроса на проверку CAdES-T (проверяется как cms)")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/CAdES_T")
    public ResponseEntity<?> CAdES_T(@RequestBody byte[] data,
                                     @RequestParam(value = "alias") String alias,
                                     @RequestParam(value = "password") String password,
                                     @RequestParam(value = "tsp") String tsp,
                                     @RequestParam(value = "isVerifySignatureOnly") boolean isVerifySignatureOnly)
            throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(CAdESUtils.createVerifyCAdES(data, alias, password, tsp, false, CAdESType.CAdES_T,
                        isVerifySignatureOnly));
    }

    @Operation(summary = "Создание запроса на проверку CAdES-T с отчётом (проверяется как cms)")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/CAdES_T_WithReport")
    public ResponseEntity<?> CAdES_T_WithReport(@RequestBody byte[] data,
                                                @RequestParam(value = "alias") String alias,
                                                @RequestParam(value = "password") String password,
                                                @RequestParam(value = "tsp") String tsp,
                                                @RequestParam(value = "isVerifySignatureOnly")
                                                        boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(CAdESUtils.createVerifyCAdESWithReport(data, alias, password, tsp, false,
                        CAdESType.CAdES_T, isVerifySignatureOnly));
    }

    @Operation(summary = "Создание запроса на проверку CAdES-T с подписанным отчётом (проверяется как cms)")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/CAdES_T_WithSignedReport")
    public ResponseEntity<?> CAdES_T_WithSignedReport(@RequestBody byte[] data,
                                                      @RequestParam(value = "alias") String alias,
                                                      @RequestParam(value = "password") String password,
                                                      @RequestParam(value = "tsp") String tsp,
                                                      @RequestParam(value = "isVerifySignatureOnly")
                                                              boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(CAdESUtils.createVerifyCAdESWithSignedReport(data, alias, password, tsp, false,
                        CAdESType.CAdES_T, isVerifySignatureOnly));
    }

    @Operation(summary = "Создание запроса на проверку CAdES-X-Long-Type 1")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/CAdES_X")
    public ResponseEntity<?> CAdES_X(@RequestBody byte[] data,
                                     @RequestParam(value = "alias") String alias,
                                     @RequestParam(value = "password") String password,
                                     @RequestParam(value = "tsp") String tsp,
                                     @RequestParam(value = "isVerifySignatureOnly") boolean isVerifySignatureOnly)
            throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(CAdESUtils.createVerifyCAdES(data, alias, password, tsp, false,
                        CAdESType.CAdES_X_Long_Type_1, isVerifySignatureOnly));
    }

    @Operation(summary = "Создание запроса на проверку CAdES-X-Long-Type 1 с отчётом")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/CAdES_X_WithReport")
    public ResponseEntity<?> CAdES_X_WithReport(@RequestBody byte[] data,
                                                @RequestParam(value = "alias") String alias,
                                                @RequestParam(value = "password") String password,
                                                @RequestParam(value = "tsp") String tsp,
                                                @RequestParam(value = "isVerifySignatureOnly")
                                                        boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(CAdESUtils.createVerifyCAdESWithReport(data, alias, password, tsp, false,
                        CAdESType.CAdES_X_Long_Type_1, isVerifySignatureOnly));
    }

    @Operation(summary = "Создание запроса на проверку CAdES-X-Long-Type 1 с подписанным отчётом")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/CAdES_X_WithSignedReport")
    public ResponseEntity<?> CAdES_X_WithSignedReport(@RequestBody byte[] data,
                                                      @RequestParam(value = "alias") String alias,
                                                      @RequestParam(value = "password") String password,
                                                      @RequestParam(value = "tsp") String tsp,
                                                      @RequestParam(value = "isVerifySignatureOnly")
                                                              boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(CAdESUtils.createVerifyCAdESWithSignedReport(data, alias, password, tsp, false,
                        CAdESType.CAdES_X_Long_Type_1, isVerifySignatureOnly));
    }

    @Operation(summary = "Создание запроса на проверку XML-DSig")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/XMLDSig")
    public ResponseEntity<?> XMLDSig(@RequestBody byte[] data,
                                     @RequestParam(value = "alias") String alias,
                                     @RequestParam(value = "password") String password,
                                     @RequestParam(value = "isVerifySignatureOnly") boolean isVerifySignatureOnly)
            throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML).body(XMLUtils.createVerifyXMLSignature(data,
                alias, password, isVerifySignatureOnly));
    }

    @Operation(summary = "Создание запроса на проверку XML-DSig с отчётом")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/XMLDSigWithReport")
    public ResponseEntity<?> XMLDSigWithReport(@RequestBody byte[] data,
                                               @RequestParam(value = "alias") String alias,
                                               @RequestParam(value = "password") String password,
                                               @RequestParam(value = "isVerifySignatureOnly")
                                                       boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(XMLUtils.createVerifyXMLSignatureWithReport(data, alias, password, isVerifySignatureOnly));
    }

    @Operation(summary = "Создание запроса на проверку XML-DSig с подписанным отчётом")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @PostMapping(value = "/XMLDSigWithSignedReport")
    public ResponseEntity<?> XMLDSigWithSignedReport(@RequestBody byte[] data,
                                                     @RequestParam(value = "alias") String alias,
                                                     @RequestParam(value = "password") String password,
                                                     @RequestParam(value = "isVerifySignatureOnly")
                                                             boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(XMLUtils.createVerifyXMLSignatureWithSignedReport(data, alias, password, isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку XAdES_BES (проверяется как XMLDSig)")
    @PostMapping(value = "/XAdES_BES", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> XAdES_BES(@RequestBody byte[] data,
                                       @RequestParam(value = "alias") String alias,
                                       @RequestParam(value = "password") String password,
                                       @RequestParam(value = "ref_acct") String ref_acct,
                                       @RequestParam(value = "isVerifySignatureOnly")
                                               boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(XAdESUtils.createVerifyXAdES(data, alias, password, null, ref_acct, XAdESType.XAdES_BES,
                        isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку XAdES_BES с отчётом (проверяется как XMLDSig)")
    @PostMapping(value = "/XAdES_BES_WithReport", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> XAdES_BESWithReport(@RequestBody byte[] data,
                                                 @RequestParam(value = "alias") String alias,
                                                 @RequestParam(value = "password") String password,
                                                 @RequestParam(value = "ref_acct") String ref_acct,
                                                 @RequestParam(value = "isVerifySignatureOnly")
                                                         boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(XAdESUtils.createVerifyXAdESWithReport(data, alias, password, null, ref_acct,
                        XAdESType.XAdES_BES, isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку XAdES_BES с подписанным отчётом (проверяется как XMLDSig)")
    @PostMapping(value = "/XAdES_BES_WithSignedReport", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> XAdES_BESWithSignedReport(@RequestBody byte[] data,
                                                       @RequestParam(value = "alias") String alias,
                                                       @RequestParam(value = "password") String password,
                                                       @RequestParam(value = "ref_acct") String ref_acct,
                                                       @RequestParam(value = "isVerifySignatureOnly")
                                                               boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(XAdESUtils.createVerifyXAdESWithSignedReport(data, alias, password, null, ref_acct,
                        XAdESType.XAdES_BES, isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку XAdES_T")
    @PostMapping(value = "/XAdES_T", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> XAdES_T(@RequestBody byte[] data,
                                     @RequestParam(value = "alias") String alias,
                                     @RequestParam(value = "password") String password,
                                     @RequestParam(value = "tsp") String tsp,
                                     @RequestParam(value = "ref_acct") String ref_acct,
                                     @RequestParam(value = "isVerifySignatureOnly") boolean isVerifySignatureOnly)
            throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(XAdESUtils.createVerifyXAdES(data, alias, password, tsp, ref_acct, XAdESType.XAdES_T,
                        isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку XAdES_T")
    @PostMapping(value = "/XAdES_T_WithReport", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> XAdES_T_WithReport(@RequestBody byte[] data,
                                                @RequestParam(value = "alias") String alias,
                                                @RequestParam(value = "password") String password,
                                                @RequestParam(value = "tsp") String tsp,
                                                @RequestParam(value = "ref_acct") String ref_acct,
                                                @RequestParam(value = "isVerifySignatureOnly")
                                                        boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(XAdESUtils.createVerifyXAdESWithReport(data, alias, password, tsp, ref_acct, XAdESType.XAdES_T,
                        isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку XAdES_T с подписанным отчётом")
    @PostMapping(value = "/XAdES_T_WithSignedReport", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> XAdES_T_WithSignedReport(@RequestBody byte[] data,
                                                      @RequestParam(value = "alias") String alias,
                                                      @RequestParam(value = "password") String password,
                                                      @RequestParam(value = "tsp") String tsp,
                                                      @RequestParam(value = "ref_acct") String ref_acct,
                                                      @RequestParam(value = "isVerifySignatureOnly")
                                                              boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(XAdESUtils.createVerifyXAdESWithSignedReport(data, alias, password, tsp, ref_acct,
                        XAdESType.XAdES_T, isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку WS-Security")
    @PostMapping(value = "/WSS", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> WSS(@RequestBody byte[] data,
                                 @RequestParam(value = "alias") String alias,
                                 @RequestParam(value = "password") String password,
                                 @RequestParam(value = "isVerifySignatureOnly") boolean isVerifySignatureOnly)
            throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(WSSecurityUtils.createVerifyWSSSignature(data, alias, password, isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку WS-Security с отчётом")
    @PostMapping(value = "/WSSWithReport", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> WSSWithReport(@RequestBody byte[] data,
                                           @RequestParam(value = "alias") String alias,
                                           @RequestParam(value = "password") String password,
                                           @RequestParam(value = "isVerifySignatureOnly")
                                                   boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(WSSecurityUtils.createVerifyWSSSignatureWithReport(data, alias, password, isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку WS-Security с подписанным отчётом")
    @PostMapping(value = "/WSSWithSignedReport", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> WSSWithSignedReport(@RequestBody byte[] data,
                                                 @RequestParam(value = "alias") String alias,
                                                 @RequestParam(value = "password") String password,
                                                 @RequestParam(value = "isVerifySignatureOnly")
                                                         boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(WSSecurityUtils.createVerifyWSSSignatureWithSignedReport(data, alias, password,
                        isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку PAdES")
    @PostMapping(value = "/PAdES", consumes = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<?> PAdES(@RequestBody byte[] dataPDF,
                                   @RequestParam(value = "alias") String alias,
                                   @RequestParam(value = "password") String password,
                                   @RequestParam(value = "tsp", required = false) String tsp,
                                   @RequestParam(value = "isVerifySignatureOnly") boolean isVerifySignatureOnly)
            throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(PAdESUtils.createVerifyPAdES(dataPDF, alias, password, tsp, isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку PAdES с отчётом")
    @PostMapping(value = "/PAdESWithReport", consumes = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<?> PAdESWithReport(@RequestBody byte[] dataPDF,
                                             @RequestParam(value = "alias") String alias,
                                             @RequestParam(value = "password") String password,
                                             @RequestParam(value = "tsp", required = false) String tsp,
                                             @RequestParam(value = "isVerifySignatureOnly")
                                                     boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(PAdESUtils.createVerifyPAdESWithReport(dataPDF, alias, password, tsp, isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку PAdES с подписанным отчётом")
    @PostMapping(value = "/PAdESWithSignedReport", consumes = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<?> PAdESWithSignedReport(@RequestBody byte[] dataPDF,
                                                   @RequestParam(value = "alias") String alias,
                                                   @RequestParam(value = "password") String password,
                                                   @RequestParam(value = "tsp", required = false) String tsp,
                                                   @RequestParam(value = "isVerifySignatureOnly")
                                                           boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(PAdESUtils.createVerifyPAdESWithSignedReport(dataPDF, alias, password, tsp,
                        isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку присоединённой CMS")
    @PostMapping(value = "/CMS")
    public ResponseEntity<?> CMS(@RequestBody byte[] data,
                                 @RequestParam(value = "alias") String alias,
                                 @RequestParam(value = "password") String password,
                                 @RequestParam(value = "isVerifySignatureOnly") boolean isVerifySignatureOnly)
            throws Exception {

        CMSUtils cmsUtils = new CMSUtils(data, alias, password, false, false,
                false, false);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(cmsUtils.createVerifyCMS(isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку присоединённой CMS с отчётом")
    @PostMapping(value = "/CMSWithReport")
    public ResponseEntity<?> CMSWithReport(@RequestBody byte[] data,
                                           @RequestParam(value = "alias") String alias,
                                           @RequestParam(value = "password") String password,
                                           @RequestParam(value = "isVerifySignatureOnly") boolean isVerifySignatureOnly)
            throws Exception {

        CMSUtils cmsUtils = new CMSUtils(data, alias, password, false, false, false,
                false);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(cmsUtils.createVerifyCMSWithReport(isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку присоединённой CMS с подписанным отчётом")
    @PostMapping(value = "/CMSWithSignedReport")
    public ResponseEntity<?> CMSWithSignedReport(@RequestBody byte[] data,
                                                 @RequestParam(value = "alias") String alias,
                                                 @RequestParam(value = "password") String password,
                                                 @RequestParam(value = "isVerifySignatureOnly")
                                                         boolean isVerifySignatureOnly) throws Exception {

        CMSUtils cmsUtils = new CMSUtils(data, alias, password, false, false,
                false, false);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(cmsUtils.createVerifyCMSWithSignedReport(isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку отсоединённой CMS с хешем")
    @PostMapping(value = "/CMShash")
    public ResponseEntity<?> CMShash(@RequestBody byte[] data,
                                     @RequestParam(value = "alias") String alias,
                                     @RequestParam(value = "password") String password,
                                     @RequestParam(value = "isVerifySignatureOnly") boolean isVerifySignatureOnly)
            throws Exception {

        CMSUtils cmsUtils = new CMSUtils(data, alias, password, true, false,
                false, false);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(cmsUtils.createVerifyCMSByHash(isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку отсоединённой CMS с хешем с отчётом")
    @PostMapping(value = "/CMShashWithReport")
    public ResponseEntity<?> CMShashWithReport(@RequestBody byte[] data,
                                               @RequestParam(value = "alias") String alias,
                                               @RequestParam(value = "password") String password,
                                               @RequestParam(value = "isVerifySignatureOnly")
                                                       boolean isVerifySignatureOnly) throws Exception {

        CMSUtils cmsUtils = new CMSUtils(data, alias, password, true, false,
                false, false);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(cmsUtils.createVerifyCMSByHashWithReport(isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку отсоединённой CMS с хешем с подписанным отчётом")
    @PostMapping(value = "/CMShashWithSignedReport")
    public ResponseEntity<?> CMShashWithSignedReport(@RequestBody byte[] data,
                                                     @RequestParam(value = "alias") String alias,
                                                     @RequestParam(value = "password") String password,
                                                     @RequestParam(value = "isVerifySignatureOnly")
                                                             boolean isVerifySignatureOnly) throws Exception {

        CMSUtils cmsUtils = new CMSUtils(data, alias, password, true, false,
                false, false);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(cmsUtils.createVerifyCMSByHashWithSignedReport(isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку отсоединённой CMS")
    @PostMapping(value = "/CMSdetached")
    public ResponseEntity<?> CMSdetached(@RequestBody byte[] data,
                                         @RequestParam(value = "alias") String alias,
                                         @RequestParam(value = "password") String password,
                                         @RequestParam(value = "isVerifySignatureOnly") boolean isVerifySignatureOnly)
            throws Exception {

        CMSUtils cmsUtils = new CMSUtils(data, alias, password, true, false,
                false, false);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(cmsUtils.createVerifyCMSDetached(isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку отсоединённой CMS с отчётом")
    @PostMapping(value = "/CMSdetachedWithReport")
    public ResponseEntity<?> CMSdetachedWithReport(@RequestBody byte[] data,
                                                   @RequestParam(value = "alias") String alias,
                                                   @RequestParam(value = "password") String password,
                                                   @RequestParam(value = "isVerifySignatureOnly")
                                                           boolean isVerifySignatureOnly) throws Exception {

        CMSUtils cmsUtils = new CMSUtils(data, alias, password, true, false,
                false, false);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(cmsUtils.createVerifyCMSDetachedWithReport(isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку отсоединённой CMS с подписанным отчётом")
    @PostMapping(value = "/CMSdetachedWithSignedReport")
    public ResponseEntity<?> CMSdetachedWithSignedReport(@RequestBody byte[] data,
                                                         @RequestParam(value = "alias") String alias,
                                                         @RequestParam(value = "password") String password,
                                                         @RequestParam(value = "isVerifySignatureOnly")
                                                                 boolean isVerifySignatureOnly) throws Exception {

        CMSUtils cmsUtils = new CMSUtils(data, alias, password, true, false,
                false, false);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(cmsUtils.createVerifyCMSDetachedWithSignedReport(isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку штампа времени." +
            "Проверяется присланный пользователем штамп времени.")
    @PostMapping(value = "/TimeStamp")
    public ResponseEntity<?> TimeStamp(@RequestBody byte[] data,
                                       @RequestParam(value = "isVerifySignatureOnly") boolean isVerifySignatureOnly)
            throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(TimeStampUtils.createVerifyTimeStamp(data, isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку штампа времени с отчётом. " +
            "Проверяется присланный пользователем штамп времени.")
    @PostMapping(value = "/TimeStampWithReport")
    public ResponseEntity<?> TimeStampWithReport(@RequestBody byte[] data,
                                                 @RequestParam(value = "isVerifySignatureOnly")
                                                         boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(TimeStampUtils.createVerifyTimeStampWithReport(data, isVerifySignatureOnly));
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/xml")})})
    @Operation(summary = "Создание запроса на проверку штампа времени с подписанным отчётом. " +
            "Проверяется присланный пользователем штамп времени.")
    @PostMapping(value = "/TimeStampWithSignedReport")
    public ResponseEntity<?> TimeStampWithSignedReport(@RequestBody byte[] data,
                                                       @RequestParam(value = "isVerifySignatureOnly")
                                                               boolean isVerifySignatureOnly) throws Exception {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML)
                .body(TimeStampUtils.createVerifyTimeStampWithSignedReport(data, isVerifySignatureOnly));
    }
}
