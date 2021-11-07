# Приложение для создания подписей

### Доступный функционал

1. Создание подписей:
* CMS присоединённая
* CMS отсоединённая
* CAdES-BES
* CAdES-T
* CAdES-X Long Type 1
* XML-DSig
* WS-Security (?)
* XAdES-BES
* XAdES-T
* PAdES (без штампа времени)
* PAdES (со штампом времени) (?)
* Штамп времени (?)

2. Создание SOAP запросов:
* VerifyAttachment (?)
* VerifyAttachmentWithReport (?)
* VerifyAttachmentWithSignedReport (?)
* VerifyCAdES
* VerifyCAdESWithReport
* VerifyCAdESWithSignedReport
* VerifyCertificate
* VerifyCertificateWithReport
* VerifyCertificateWithSignedReport
* VerifyCMSSignature
* VerifyCMSSignatureWithReport
* VerifyCMSSignatureWithSignedReport
* VerifyCMSSignatureByHash
* VerifyCMSSignatureByHashWithReport
* VerifyCMSSignatureByHashWithSignedReport
* VerifyCMSSignatureDetached
* VerifyCMSSignatureDetachedWithReport
* VerifyCMSSignatureDetachedWithSignedReport
* VerifyPAdES
* VerifyPAdESWithReport
* VerifyPAdESWithSignedReport
* VerifyTimeStamp
* VerifyTimeStampWithReport
* VerifyTimeStampWithSignedReport
* VerifyWSSSignature
* VerifyWSSSignatureWithReport
* VerifyWSSSignatureWithSignedReport
* VerifyXAdES
* VerifyXAdESWithReport
* VerifyXAdESWithSignedReport
* VerifyXMLSignature
* VerifyXMLSignatureWithReport
* VerifyXMLSignatureWithSignedReport

### Используемые инструменты
* Java 11
* CryptoPro JCP 2.0.41940-A
* Spring Boot

### Инструкция по добавлению корневого сертификата в cacerts Windows
* cd "C:\Program Files\Java\jdk-11.0.13\bin"
* keytool -importcert -trustcacerts -alias <Название сертификата> -keystore "C:\Program Files\Java\jdk-11.0.13\lib\security\cacerts" -file "<путь до сертификата>" (Пароль: changeit)
