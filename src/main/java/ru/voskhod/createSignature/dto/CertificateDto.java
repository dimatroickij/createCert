package ru.voskhod.createSignature.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;
import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CertificateDto {

    @NotBlank
    @Schema(description = "CN")
    private String CommonName;

//    @NotBlank
//    @Schema(description = "SN")
//    private String SurName;
//
//    @NotBlank
//    @Schema(description = "GN")
//    private String GivenName;
//
//    @Schema(description = "C")
//    private String Country;
//
//    @Schema(description = "ST")
//    private String ST;
//
//    @Schema(description = "L")
//    private String L;
//
//    @Schema(description = "EMAILADDRESS")
//    private String Email;

    @NotBlank
    @Schema(description = "Alias - Название контейнера")
    private String Alias;

    @NotBlank
    @Schema(description = "Алгоритм сертификата")
    private String Algorithm;

    @NotBlank
    @Schema(description = "Серийный номер")
    private String Serial;

    @NotBlank
    @Schema(description = "Отпечаток")
    private String Thumbprint;

    @NotBlank
    @Schema(type = "string", pattern = "^(0[1-9]|[12][0-9]|3[01])\\.(0[1-9]|1[012]).\\d{4} ([0-1]\\d|[2][0-3]|3[01]):([0-5]\\d):([0-5]\\d)$",
            description = "Действителен с", example = "dd.MM.yyyy HH:mm:ss")
    private Date NotBefore;

    @NotBlank
    @Schema(type = "string", pattern = "^(0[1-9]|[12][0-9]|3[01])\\.(0[1-9]|1[012]).\\d{4} ([0-1]\\d|[2][0-3]|3[01]):([0-5]\\d):([0-5]\\d)$",
            description = "Действителен по", example = "dd.MM.yyyy HH:mm:ss")
    private Date NotAfter;
}
