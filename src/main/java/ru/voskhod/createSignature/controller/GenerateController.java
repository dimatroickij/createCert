package ru.voskhod.createSignature.controller;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.PdfWriter;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.java.Log;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.XAdES.XAdESType;
import ru.voskhod.createSignature.utils.*;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Random;

@RestController
@RequestMapping("/generate")
@Log
@Tag(name = "Generate", description = "Генерация данных для НТ")
public class GenerateController {

    @Operation(summary = "Создание файлов для SOAP адаптера")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", content = {@Content(mediaType = "text/plain")})})
    @PostMapping(value = "/all")
    public ResponseEntity<?> all(@RequestBody @Parameter(description = "Путь до папки, в которую будут сохраняться " +
            "файлы") String path, @Parameter(description = "Alias контейнера") @RequestParam String alias,
                                 @Parameter(description = "Пароль от контейнера") @RequestParam String password,
                                 @Parameter(description = "Адрес TSP сервера") @RequestParam String tsp,
                                 @Parameter(description = "Количество файлов") @RequestParam Integer count,
                                 @Parameter(description = "Начальный номер файла") @RequestParam Integer start,
                                 @Parameter(description = "Размер файла в КБ") @RequestParam Integer size,
                                 @Parameter(description = "CMS присоединённая?") @RequestParam boolean isCMSatt,
                                 @Parameter(description = "CMS отсоединённая?") @RequestParam boolean isCMSdet,
                                 @Parameter(description = "CAdES?") @RequestParam boolean isCAdES,
                                 @Parameter(description = "XMLDSig?") @RequestParam boolean isXMLDSig,
                                 @Parameter(description = "XAdES?") @RequestParam boolean isXAdES,
                                 @Parameter(description = "PAdES?") @RequestParam boolean isPAdES) throws Exception {
        Random random = new Random();
        File directory = new File(path);
        if (!directory.exists()) {
            directory.mkdir();
        }
        int i = 0;
        if (directory.isDirectory()) {
            for (i = start; i < count + start; i++) {
                byte[] data = new byte[(size) * 1024];
                String xml = "<?xml version=\"1.0\"?>\n" +
                        "<PatientRecord>\n" +
                        "    <Account Id=\"acct\">{%data%}</Account>\n" +
                        "</PatientRecord>\n";
                byte[] xmlByte = xml.replace("{%data%}", Base64.toBase64String(data)).getBytes(StandardCharsets.UTF_8);
                random.nextBytes(data);
                if (isCMSatt) {
                    CMSUtils CMSatt = new CMSUtils(data, alias, password, false, false, false, false);
                    FileOutputStream SoapCMSatt = new FileOutputStream(path + "\\VerifyCMSSignature_simple_" + String.valueOf(i) + ".xml");
                    SoapCMSatt.write(CMSatt.createVerifyCMS(false));
                    SoapCMSatt.close();
                    FileOutputStream SoapCMSattWithSignedReport = new FileOutputStream(path + "\\VerifyCMSSignature_withSignedReport_" + String.valueOf(i) + ".xml");
                    SoapCMSattWithSignedReport.write(CMSatt.createVerifyCMSWithSignedReport(false));
                    SoapCMSattWithSignedReport.close();
                }
                if (isCMSdet) {
                    CMSUtils CMSdet = new CMSUtils(data, alias, password, true, false, false,
                            false);
                    FileOutputStream SoapCMSdet = new FileOutputStream(path + "\\VerifyCMSSignatureDetached_simple_" + String.valueOf(i) + ".xml");
                    SoapCMSdet.write(CMSdet.createVerifyCMSDetached(false));
                    SoapCMSdet.close();
                    FileOutputStream SoapCMSdetWithSignedReport = new FileOutputStream(path + "\\VerifyCMSSignatureDetached_withSignedReport_" + String.valueOf(i) + ".xml");
                    SoapCMSdetWithSignedReport.write(CMSdet.createVerifyCMSDetachedWithSignedReport(false));
                    SoapCMSdetWithSignedReport.close();
                    FileOutputStream SoapCMSdetHash = new FileOutputStream(path + "\\VerifyCMSSignatureByHash_simple_" + String.valueOf(i) + ".xml");
                    SoapCMSdetHash.write(CMSdet.createVerifyCMSByHash(false));
                    SoapCMSdetHash.close();
                    FileOutputStream SoapCMSdetHashWithSignedReport = new FileOutputStream(path + "\\VerifyCMSSignatureByHash_withSignedReport_" + String.valueOf(i) + ".xml");
                    SoapCMSdetHashWithSignedReport.write(CMSdet.createVerifyCMSByHashWithSignedReport(false));
                    SoapCMSdetHashWithSignedReport.close();
                }

                if (isCAdES) {
                    byte[] CAdES = CAdESUtils.createCAdES(data, alias, password, tsp, false,
                            CAdESType.CAdES_X_Long_Type_1);
                    FileOutputStream SoapCAdES_BES = new FileOutputStream(path + "\\VerifyCAdES_simple_" + String.valueOf(i) + ".xml");
                    SoapCAdES_BES.write(CAdESUtils.createVerifyCAdES(CAdES, CAdESType.CAdES_X_Long_Type_1, false));
                    SoapCAdES_BES.close();
                    FileOutputStream SoapCAdES_BES_WithSignedReport = new FileOutputStream(path + "\\VerifyCAdES_withSignedReport_" + String.valueOf(i) + ".xml");
                    SoapCAdES_BES_WithSignedReport.write(CAdESUtils.createVerifyCAdESWithSignedReport(CAdES,
                            CAdESType.CAdES_X_Long_Type_1, false));
                    SoapCAdES_BES_WithSignedReport.close();
                }

                // Добавление сгенерированных данных в XML не работает
                if (isXMLDSig) {
                    byte[] XMLDSig = XMLUtils.createXMLDSig(xmlByte, alias, password);
                    FileOutputStream SoapXML_DSig = new FileOutputStream(path + "\\VerifyXMLSignature_simple_" + String.valueOf(i) + ".xml");
                    SoapXML_DSig.write(XMLUtils.createVerifyXMLSignature(XMLDSig, false));
                    SoapXML_DSig.close();
                    FileOutputStream SoapXML_DSigWithSignedReport = new FileOutputStream(path +
                            "\\VerifyXMLSignature_withSignedReport_" + String.valueOf(i) + ".xml");
                    SoapXML_DSigWithSignedReport.write(XMLUtils.createVerifyXMLSignatureWithSignedReport(XMLDSig,
                            false));
                    SoapXML_DSigWithSignedReport.close();
                }

                // Добавление сгенерированных данных в XML не работает
                if (isXAdES) {
                    byte[] XAdES = XAdESUtils.createXAdES(xmlByte, alias, password, tsp, "acct", XAdESType.XAdES_T);
                    FileOutputStream SoapXAdES = new FileOutputStream(path + "\\VerifyXAdES_simple_" + String.valueOf(i) + ".xml");
                    SoapXAdES.write(XAdESUtils.createVerifyXAdES(XAdES, XAdESType.XAdES_T, false));
                    SoapXAdES.close();
                    FileOutputStream SoapXAdES_WithSignedReport = new FileOutputStream(path +
                            "\\VerifyXAdES_WithSignedReport_" + String.valueOf(i) + ".xml");
                    SoapXAdES_WithSignedReport.write(XAdESUtils.createVerifyXAdESWithSignedReport(XAdES, XAdESType.XAdES_T,
                            false));
                    SoapXAdES_WithSignedReport.close();
                }

                Document document = new Document();
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                PdfWriter.getInstance(document, outputStream);

                document.open();
                Font font = FontFactory.getFont(FontFactory.COURIER, 16, BaseColor.BLACK);
                byte[] array = new byte[size * 1024]; // length is bounded by 7
                Chunk chunk = new Chunk(new String(array, StandardCharsets.UTF_8), font);
                document.add(chunk);
                document.close();

                if (isPAdES) {
                    byte[] PAdES = PAdESUtils.createPAdES (outputStream.toByteArray(), alias, password, tsp);
                    FileOutputStream SoapPAdES = new FileOutputStream(path + "\\VerifyPAdES_simple_" + String.valueOf(i) + ".xml");
                    SoapPAdES.write(PAdESUtils.createVerifyPAdES(PAdES, false));
                    SoapPAdES.close();
                    FileOutputStream SoapPAdES_WithSignedReport = new FileOutputStream(path +
                            "\\VerifyPAdES_WithSignedReport_" + String.valueOf(i) + ".xml");
                    SoapPAdES_WithSignedReport.write(PAdESUtils.createVerifyPAdESWithSignedReport(PAdES,
                            false));
                    SoapPAdES_WithSignedReport.close();
                }

            }
            return ResponseEntity.ok().body("Файлы сохранены в указанную папку");
        }
        return ResponseEntity.status(400).body("Неправильный путь до папки");
    }
}
