package ru.voskhod.createSignature;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import ru.CryptoPro.JCP.JCP;

import java.security.Security;

@SpringBootApplication
public class CreateSignatureApplication {

    public static void main(String[] args) {
        Security.addProvider(new JCP());
        SpringApplication.run(CreateSignatureApplication.class, args);
    }

}
