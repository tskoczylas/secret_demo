package com.prototal.usersecret.services;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(properties = {
        "encryption.algorithm=AES",
        "encryption.salt=1"
})
class EncryptionServiceImpTestWrongKey {
    @Autowired
    EncryptionService encryptionService;

    final String textToEncrypt = "text";

    @Test
    void encryptShouldThrownStateExertionWhenWrongKeyOrAlgorithm() {
        //given
        Exception exception = assertThrows(Exception.class, () -> {
            String encryptedSpring = encryptionService.encrypt(textToEncrypt);
        });
        //then
        assertEquals("Error while encrypting", exception.getMessage());

    }

    @Test
    void decryptShouldThrownStateExertionWhenWrongKeyOrAlgorithm() {
        //given
        Exception exception = assertThrows(Exception.class, () -> {
            String encryptedSpring = encryptionService.decrypt(textToEncrypt);
        });
        //then
        assertEquals("Error while decrypting", exception.getMessage());

    }
}