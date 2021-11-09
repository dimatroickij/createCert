package ru.voskhod.createSignature.controller;

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
import ru.voskhod.createSignature.utils.CAdESUtils;
import ru.voskhod.createSignature.utils.CMSUtils;
import ru.voskhod.createSignature.utils.XAdESUtils;
import ru.voskhod.createSignature.utils.XMLUtils;

import java.io.File;
import java.io.FileOutputStream;
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
                                 @Parameter(description = "XAdES-T?") @RequestParam boolean isXAdES,
                                 @Parameter(description = "PAdES?") @RequestParam boolean isPAdES) throws Exception {
        Random random = new Random();
        File directory = new File(path);
        if (!directory.exists()) {
            directory.mkdir();
        }
        int i = 0;
        if (directory.isDirectory()) {
            byte[] data = new byte[(size) * 1024 - 97];
            String xml = "<?xml version=\"1.0\"?>\n" +
                    "<PatientRecord>\n" +
                    "    <Account Id=\"acct\">{%data%}</Account>\n" +
                    "</PatientRecord>\n";

            random.nextBytes(data);
            for (i = start; i < count + start; i++) {
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
                    byte[] XMLDSig = XMLUtils.createXMLDSig(xml.replace("{%data%}", Base64.toBase64String(data)).getBytes(StandardCharsets.UTF_8), alias, password);
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
                    byte[] XAdES_T = XAdESUtils.createXAdES(xml.replace("{%data%}", Base64.toBase64String(data)).getBytes(StandardCharsets.UTF_8), alias, password, tsp, "acct", XAdESType.XAdES_T);
                    FileOutputStream SoapXAdES_T = new FileOutputStream(path + "\\VerifyXAdES_simple_" + String.valueOf(i) + ".xml");
                    SoapXAdES_T.write(XAdESUtils.createVerifyXAdES(XAdES_T, XAdESType.XAdES_T, false));
                    SoapXAdES_T.close();
                    FileOutputStream SoapXAdES_T_WithSignedReport = new FileOutputStream(path +
                            "\\VerifyXAdES_WithSignedReport_" + String.valueOf(i) + ".xml");
                    SoapXAdES_T_WithSignedReport.write(XAdESUtils.createVerifyXAdESWithSignedReport(XAdES_T, XAdESType.XAdES_T,
                            false));
                    SoapXAdES_T_WithSignedReport.close();
                }

                // TODO
                // PAdES

            }
            return ResponseEntity.ok().body("Файлы сохранены в указанную папку");
        }
        return ResponseEntity.status(400).body("Неправильный путь до папки");
    }
}
