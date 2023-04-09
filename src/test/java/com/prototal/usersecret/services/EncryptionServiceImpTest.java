package com.prototal.usersecret.services;

import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(properties = {
        "encryption.algorithm=AES",
        "encryption.key=OXokQyZGKUpATmNSZlVqVw=="
})
class EncryptionServiceImpTest {
    @Autowired
    EncryptionService encryptionService;

    final String textToEncrypt = "test";

    @Test
    void encryptDecrypt() {
        //given
        String encryptedSpring = encryptionService.encrypt(textToEncrypt);
        //then
        assertNotEquals(encryptedSpring, textToEncrypt);

        //given
        String decryptedString = encryptionService.decrypt(encryptedSpring);
        //then
        assertEquals(decryptedString, textToEncrypt);
    }
}