package ru.voskhod.createSignature.controller;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.PdfWriter;
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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;

@RestController
@RequestMapping("/signature")
@Log
@Tag(name = "Signature", description = "Работа с подписями")
public class SignatureController {

    public SignatureController() {
        JCPXMLDSigInit.init();
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
                          @RequestParam boolean isDetached) throws Exception {
        return CAdESUtils.createCAdES(data, alias, password, tsp, isDetached, CAdESType.CAdES_T);
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
                          @RequestParam boolean isDetached) throws Exception {
        return CAdESUtils.createCAdES(data, alias, password, tsp, isDetached, CAdESType.CAdES_X_Long_Type_1);
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
                                         "присоединённая (false)") @RequestParam boolean isDetached) throws Exception {

        // Добавление или исключение подписанных атрибутов
        boolean isContentType = false;
        boolean isTime = false;
        boolean isSigningCertificateV2 = false;
        CMSUtils cmsUtils = new CMSUtils(data, alias, password, isDetached, isContentType, isTime,
                isSigningCertificateV2);
        byte[] signature = cmsUtils.getSignature();
        byte[] digest = cmsUtils.getDigest();
        String hash = cmsUtils.getHash();
        return ResponseEntity.status(HttpStatus.OK).header("Hash-Data", hash).body(signature);
    }

    @ApiResponses(value = {@ApiResponse(responseCode = "200")})
    @Operation(summary = "Создание штампа времени")
    @PostMapping(value = "/Timestamp", consumes = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<?> Timestamp(@Parameter(description = "Alias контейнера") @RequestParam String alias,
                                       @Parameter(description = "Адрес TSP сервера") @RequestParam String tsp)
            throws Exception {
        return ResponseEntity.status(HttpStatus.OK).body(TimeStampUtils.createTimeStamp(alias, tsp));
    }

    @Operation(summary = "Создание подписей всех типов")
    @PostMapping(value = "/createAllSignature", consumes = "text/plain")
    public ResponseEntity<?> createAllSignature(@RequestBody @Parameter(description = "Путь до папки, в которую " +
            "будут сохраняться подписи") String path,
                                                @Parameter(description = "Alias контейнера") @RequestParam String alias,
                                                @Parameter(description = "Пароль от контейнера")
                                                @RequestParam String password,
                                                @Parameter(description = "Адрес TSP сервера") @RequestParam String tsp)
            throws Exception {
        File directory = new File(path);
        if (directory.isDirectory()) {

            new File(path + "\\SOAP").mkdir();
            new File(path + "\\FILE").mkdir();
            // Создание данных, которые будут подписываться

            byte[] text = "Hello World".getBytes(StandardCharsets.UTF_8);
            FileOutputStream textFile = new FileOutputStream(path + "\\FILE\\file.txt");
            textFile.write(text);
            textFile.close();

            String xml = "<?xml version=\"1.0\"?>\n" +
                    "<PatientRecord>\n" +
                    "    <Name>John Doe</Name>\n" +
                    "    <Account Id=\"acct\">123456</Account>\n" +
                    "    <BankInfo Id=\"bank\">HomeBank</BankInfo>\n" +
                    "    <Visit date=\"10pm March 10, 2002\">\n" +
                    "        <Diagnosis>Broken second metacarpal111</Diagnosis>\n" +
                    "    </Visit>\n" +
                    "</PatientRecord>\n";
            byte[] xmlByte = xml.getBytes(StandardCharsets.UTF_8);
            FileOutputStream xmlFile = new FileOutputStream(path + "\\FILE\\file.xml");
            xmlFile.write(xmlByte);
            xmlFile.close();

            Document document = new Document();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            PdfWriter.getInstance(document, outputStream);

            document.open();
            Font font = FontFactory.getFont(FontFactory.COURIER, 16, BaseColor.BLACK);
            Chunk chunk = new Chunk("Hello World", font);

            document.add(chunk);
            document.close();
            FileOutputStream pdfFile = new FileOutputStream(path + "\\FILE\\file.pdf");
            pdfFile.write(outputStream.toByteArray());
            pdfFile.close();

            // CMS присоединённая
            CMSUtils CMSatt = new CMSUtils(text, alias, password, false, false, false,
                    false);
            FileOutputStream FileCMSatt = new FileOutputStream(path + "\\CMS (att.).sig");
            FileCMSatt.write(CMSatt.getSignature());
            FileCMSatt.close();
            FileOutputStream SoapCMSatt = new FileOutputStream(path + "\\SOAP\\CMS (att.).xml");
            SoapCMSatt.write(CMSatt.createVerifyCMS(false));
            SoapCMSatt.close();
            FileOutputStream SoapCMSattWithReport = new FileOutputStream(path +
                    "\\SOAP\\CMS (att.) WithReport.xml");
            SoapCMSattWithReport.write(CMSatt.createVerifyCMSWithReport(false));
            SoapCMSattWithReport.close();
            FileOutputStream SoapCMSattWithSignedReport = new FileOutputStream(path +
                    "\\SOAP\\CMS (att.) WithSignedReport.xml");
            SoapCMSattWithSignedReport.write(CMSatt.createVerifyCMSWithSignedReport(false));
            SoapCMSattWithSignedReport.close();

            // CMS отсоединённая
            CMSUtils CMSdet = new CMSUtils(text, alias, password, true, false, false,
                    false);
            FileOutputStream FileCMSdet = new FileOutputStream(path + "\\CMS (det.).sig");
            FileCMSdet.write(CMSdet.getSignature());
            FileCMSdet.close();
            FileOutputStream SoapCMSdet = new FileOutputStream(path + "\\SOAP\\CMS (det.).xml");
            SoapCMSdet.write(CMSdet.createVerifyCMSDetached(false));
            SoapCMSdet.close();
            FileOutputStream SoapCMSdetWithReport = new FileOutputStream(path +
                    "\\SOAP\\CMS (det.) WithReport.xml");
            SoapCMSdetWithReport.write(CMSdet.createVerifyCMSDetachedWithReport(false));
            SoapCMSdetWithReport.close();
            FileOutputStream SoapCMSdetWithSignedReport = new FileOutputStream(path +
                    "\\SOAP\\CMS (det.) WithSignedReport.xml");
            SoapCMSdetWithSignedReport.write(CMSdet.createVerifyCMSDetachedWithSignedReport(false));
            SoapCMSdetWithSignedReport.close();
            FileOutputStream SoapCMSdetHash = new FileOutputStream(path + "\\SOAP\\CMS (det.) hash.xml");
            SoapCMSdetHash.write(CMSdet.createVerifyCMSByHash(false));
            SoapCMSdetHash.close();
            FileOutputStream SoapCMSdetHashWithReport = new FileOutputStream(path +
                    "\\SOAP\\CMS (det.) hash WithReport.xml");
            SoapCMSdetHashWithReport.write(CMSdet.createVerifyCMSByHashWithReport(false));
            SoapCMSdetHashWithReport.close();
            FileOutputStream SoapCMSdetHashWithSignedReport = new FileOutputStream(path
                    + "\\SOAP\\CMS (det.) hash WithSignedReport.xml");
            SoapCMSdetHashWithSignedReport.write(CMSdet.createVerifyCMSByHashWithSignedReport(false));
            SoapCMSdetHashWithSignedReport.close();

            // Сохранение дайжеста и хеша от отсоединённой CMS
            FileOutputStream FileCMSdetDigest = new FileOutputStream(path + "\\CMS (det.).sig.hash");
            FileCMSdetDigest.write(CMSdet.getDigest());
            FileCMSdetDigest.close();

            FileOutputStream FileCMSdetHash = new FileOutputStream(path + "\\CMS (det.) hash.txt");
            FileCMSdetHash.write(CMSdet.getHash().getBytes(StandardCharsets.UTF_8));
            FileCMSdetHash.close();

            // CAdES-BES
            FileOutputStream FileCAdES_BES = new FileOutputStream(path + "\\CAdES-BES.sig");
            byte[] CAdES_BES = CAdESUtils.createCAdES(text, alias, password, null, false,
                    CAdESType.CAdES_BES);
            FileCAdES_BES.write(CAdES_BES);
            FileCAdES_BES.close();
            FileOutputStream SoapCAdES_BES = new FileOutputStream(path + "\\SOAP\\CAdES-BES.xml");
            SoapCAdES_BES.write(CAdESUtils.createVerifyCAdES(CAdES_BES, CAdESType.CAdES_BES, false));
            SoapCAdES_BES.close();
            FileOutputStream SoapCAdES_BES_WithReport = new FileOutputStream(path +
                    "\\SOAP\\CAdES-BES WithReport.xml");
            SoapCAdES_BES_WithReport.write(CAdESUtils.createVerifyCAdESWithReport(CAdES_BES, CAdESType.CAdES_BES,
                    false));
            SoapCAdES_BES_WithReport.close();
            FileOutputStream SoapCAdES_BES_WithSignedReport = new FileOutputStream(path +
                    "\\SOAP\\CAdES-BES WithSignedReport.xml");
            SoapCAdES_BES_WithSignedReport.write(CAdESUtils.createVerifyCAdESWithSignedReport(CAdES_BES,
                    CAdESType.CAdES_BES, false));
            SoapCAdES_BES_WithSignedReport.close();

            // CAdES-T
            FileOutputStream FileCAdES_T = new FileOutputStream(path + "\\CAdES-T.sig");
            byte[] CAdES_T = CAdESUtils.createCAdES(text, alias, password, tsp, false, CAdESType.CAdES_T);
            FileCAdES_T.write(CAdES_T);
            FileCAdES_T.close();
            FileOutputStream SoapCAdES_T = new FileOutputStream(path + "\\SOAP\\CAdES-T.xml");
            SoapCAdES_T.write(CAdESUtils.createVerifyCAdES(CAdES_T, CAdESType.CAdES_T, false));
            SoapCAdES_T.close();
            FileOutputStream SoapCAdES_T_WithReport = new FileOutputStream(path +
                    "\\SOAP\\CAdES-T WithReport.xml");
            SoapCAdES_T_WithReport.write(CAdESUtils.createVerifyCAdESWithReport(CAdES_T, CAdESType.CAdES_T,
                    false));
            SoapCAdES_T_WithReport.close();
            FileOutputStream SoapCAdES_T_WithSignedReport = new FileOutputStream(path +
                    "\\SOAP\\CAdES-T WithSignedReport.xml");
            SoapCAdES_T_WithSignedReport.write(CAdESUtils.createVerifyCAdESWithSignedReport(CAdES_T,
                    CAdESType.CAdES_T, false));
            SoapCAdES_T_WithSignedReport.close();

            // CAdES-X
            FileOutputStream FileCAdES_X = new FileOutputStream(path + "\\CAdES-X Long Type 1.sig");
            byte[] CAdES_X = CAdESUtils.createCAdES(text, alias, password, tsp, false,
                    CAdESType.CAdES_X_Long_Type_1);
            FileCAdES_X.write(CAdES_X);
            FileCAdES_X.close();
            FileOutputStream SoapCAdES_X = new FileOutputStream(path + "\\SOAP\\CAdES-X Long Type 1.xml");
            SoapCAdES_X.write(CAdESUtils.createVerifyCAdES(CAdES_X, CAdESType.CAdES_X_Long_Type_1,
                    false));
            SoapCAdES_X.close();
            FileOutputStream SoapCAdES_X_WithReport = new FileOutputStream(path +
                    "\\SOAP\\CAdES-X Long Type 1 WithReport.xml");
            SoapCAdES_X_WithReport.write(CAdESUtils.createVerifyCAdESWithReport(CAdES_X, CAdESType.CAdES_X_Long_Type_1,
                    false));
            SoapCAdES_X_WithReport.close();
            FileOutputStream SoapCAdES_X_WithSignedReport = new FileOutputStream(path +
                    "\\SOAP\\CAdES-X Long Type 1 WithSignedReport.xml");
            SoapCAdES_X_WithSignedReport.write(CAdESUtils.createVerifyCAdESWithSignedReport(CAdES_X,
                    CAdESType.CAdES_X_Long_Type_1, false));
            SoapCAdES_X_WithSignedReport.close();

            // XML-DSig
            FileOutputStream FileXML_DSig = new FileOutputStream(path + "\\XML-DSig.xml");
            byte[] XML_DSig = XMLUtils.createXMLDSig(xmlByte, alias, password);
            FileXML_DSig.write(XML_DSig);
            FileXML_DSig.close();
            FileOutputStream SoapXML_DSig = new FileOutputStream(path + "\\SOAP\\XML-DSig.xml");
            SoapXML_DSig.write(XMLUtils.createVerifyXMLSignature(XML_DSig, false));
            SoapXML_DSig.close();
            FileOutputStream SoapXML_DSigWithReport = new FileOutputStream(path +
                    "\\SOAP\\XML-DSig WithReport.xml");
            SoapXML_DSigWithReport.write(XMLUtils.createVerifyXMLSignatureWithReport(XML_DSig, false));
            SoapXML_DSigWithReport.close();
            FileOutputStream SoapXML_DSigWithSignedReport = new FileOutputStream(path +
                    "\\SOAP\\XML-DSig WithSignedReport.xml");
            SoapXML_DSigWithSignedReport.write(XMLUtils.createVerifyXMLSignatureWithSignedReport(XML_DSig,
                    false));
            SoapXML_DSigWithSignedReport.close();

            // XAdES-BES
            FileOutputStream FileXAdES_BES = new FileOutputStream(path + "\\XAdES-BES.xml");
            byte[] XAdES_BES = XAdESUtils.createXAdES(xmlByte, alias, password, null, "acct",
                    XAdESType.XAdES_BES);
            FileXAdES_BES.write(XAdES_BES);
            FileXAdES_BES.close();
            FileOutputStream SoapXAdES_BES = new FileOutputStream(path + "\\SOAP\\XAdES-BES.xml");
            SoapXAdES_BES.write(XMLUtils.createVerifyXMLSignature(XAdES_BES, false));
            SoapXAdES_BES.close();
            FileOutputStream SoapXAdES_BESWithReport = new FileOutputStream(path +
                    "\\SOAP\\XAdES-BES WithReport.xml");
            SoapXAdES_BESWithReport.write(XMLUtils.createVerifyXMLSignatureWithReport(XAdES_BES, false));
            SoapXAdES_BESWithReport.close();
            FileOutputStream SoapXAdES_BESWithSignedReport = new FileOutputStream(path +
                    "\\SOAP\\XAdES-BES WithSignedReport.xml");
            SoapXAdES_BESWithSignedReport.write(XMLUtils.createVerifyXMLSignatureWithSignedReport(XAdES_BES,
                    false));
            SoapXAdES_BESWithSignedReport.close();

            // XAdES-T
            FileOutputStream FileXAdES_T = new FileOutputStream(path + "\\XAdES-T.xml");
            byte[] XAdES_T = XAdESUtils.createXAdES(xmlByte, alias, password, tsp, "acct", XAdESType.XAdES_T);
            FileXAdES_T.write(XAdES_T);
            FileXAdES_T.close();
            FileOutputStream SoapXAdES_T = new FileOutputStream(path + "\\SOAP\\XAdES-T.xml");
            SoapXAdES_T.write(XAdESUtils.createVerifyXAdES(XAdES_T, XAdESType.XAdES_T, false));
            SoapXAdES_T.close();
            FileOutputStream SoapXAdES_T_WithReport = new FileOutputStream(path +
                    "\\SOAP\\XAdES-T WithReport.xml");
            SoapXAdES_T_WithReport.write(XAdESUtils.createVerifyXAdESWithReport(XAdES_T, XAdESType.XAdES_T,
                    false));
            SoapXAdES_T_WithReport.close();
            FileOutputStream SoapXAdES_T_WithSignedReport = new FileOutputStream(path +
                    "\\SOAP\\XAdES-T WithSignedReport.xml");
            SoapXAdES_T_WithSignedReport.write(XAdESUtils.createVerifyXAdESWithSignedReport(XAdES_T, XAdESType.XAdES_T,
                    false));
            SoapXAdES_T_WithSignedReport.close();

            // PAdES без штампа времени
            FileOutputStream FilePAdES = new FileOutputStream(path + "\\PAdES (без штампа времени).pdf");
            byte[] PAdES = PAdESUtils.createPAdES(outputStream.toByteArray(), alias, password, tsp);
            FilePAdES.write(PAdES);
            FilePAdES.close();
            FileOutputStream SoapPAdES = new FileOutputStream(path + "\\SOAP\\PAdES (без штампа времени).xml");
            SoapPAdES.write(PAdESUtils.createVerifyPAdES(PAdES, false));
            SoapPAdES.close();
            FileOutputStream SoapPAdESWithReport = new FileOutputStream(path +
                    "\\SOAP\\PAdES (без штампа времени) WithReport.xml");
            SoapPAdESWithReport.write(PAdESUtils.createVerifyPAdESWithReport(PAdES, false));
            SoapPAdESWithReport.close();
            FileOutputStream SoapPAdESWithSignedReport = new FileOutputStream(path +
                    "\\SOAP\\PAdES (без штампа времени) WithSignedReport.xml");
            SoapPAdESWithSignedReport.write(PAdESUtils.createVerifyPAdESWithSignedReport(PAdES, false));
            SoapPAdESWithSignedReport.close();

            // PAdES (со штампом времени) пока не генерируется

            // WS-Security
            // Пока возвращает xmlByte
            FileOutputStream FileWSS = new FileOutputStream(path + "\\WS-Security.xml");
            byte[] WSS = WSSecurityUtils.createWSS(xmlByte, alias, password);
            FileWSS.write(WSS);
            FileWSS.close();
            FileOutputStream SoapWSS = new FileOutputStream(path + "\\SOAP\\WS-Security.xml");
            SoapWSS.write(WSSecurityUtils.createVerifyWSSSignature(WSS, false));
            SoapWSS.close();
            FileOutputStream SoapWSSWithReport = new FileOutputStream(path +
                    "\\SOAP\\WS-Security WithReport.xml");
            SoapWSSWithReport.write(WSSecurityUtils.createVerifyWSSSignatureWithReport(WSS, false));
            SoapWSSWithReport.close();
            FileOutputStream SoapWSSWithSignedReport = new FileOutputStream(path +
                    "\\SOAP\\WS-Security WithSignedReport.xml");
            SoapWSSWithSignedReport.write(WSSecurityUtils.createVerifyWSSSignatureWithSignedReport(WSS,
                    false));
            SoapWSSWithSignedReport.close();

//            // Штамп времени
//            FileOutputStream FileTimestamp = new FileOutputStream(path + "\\Timestamp.tsr");
//            byte[] Timestamp = TimeStampUtils.createTimeStamp(alias, tsp);
//            FileTimestamp.write(Timestamp);
//            FileTimestamp.close();
//            FileOutputStream SoapTimestamp = new FileOutputStream(path + "\\SOAP\\Timestamp.xml");
//            SoapTimestamp.write(TimeStampUtils.createVerifyTimeStamp(Timestamp, false));
//            SoapTimestamp.close();
//            FileOutputStream SoapTimestampWithReport = new FileOutputStream(path +
//                    "\\SOAP\\Timestamp WithReport.xml");
//            SoapTimestampWithReport.write(TimeStampUtils.createVerifyTimeStampWithReport(Timestamp,
//                    false));
//            SoapTimestampWithReport.close();
//            FileOutputStream SoapTimestampWithSignedReport = new FileOutputStream(path +
//                    "\\SOAP\\Timestamp WithSignedReport.xml");
//            SoapTimestampWithSignedReport.write(TimeStampUtils.createVerifyTimeStampWithSignedReport(Timestamp,
//                    false));
//            SoapTimestampWithSignedReport.close();

            return ResponseEntity.ok().body("Подписи сохранены в указанную папку");
        }
        return ResponseEntity.status(400).body("Неправильный путь до папки");
    }
}
