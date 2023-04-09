package com.prototal.usersecret.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;


/**
 * The EncryptionService implementation providing methods to encrypt and decrypt for provided in properties Salt and algorithm type
 */
@Service
public class EncryptionServiceImp implements EncryptionService {

    /**
     * The Encryption salt.
     */
    @Value("${encryption.salt}")
    private String encryptionSalt;

    /**
     * The Algorithm.
     */
    @Value("${encryption.algorithm}")
    private String algorithm;

    /**
     * Preparing  128 bit salt key used for encryption
     *
     * @return the SecretKeySpec used for decrypt and encrypt
     * @throws NoSuchAlgorithmException the no such algorithm exception
     */
    private SecretKeySpec prepareSecreteKey() throws NoSuchAlgorithmException {

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        byte[] decodeSecretKry = Base64.getDecoder().decode(encryptionSalt);
        return new SecretKeySpec(decodeSecretKry, "AES");
    }

    /**
     * Encrypt string.
     *
     * @param strToEncrypt String to encryption
     * @return encrypted string
     * @throws IllegalStateException with any nested error
     */
    public String encrypt(String strToEncrypt) {
        try {
            SecretKeySpec secretKeySpec = prepareSecreteKey();
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
            throw new IllegalStateException("Error while encrypting", e);
        }
    }

    /**
     * decrypt string.
     *
     * @param strToDecrypt String to decryption
     * @return decrypted string
     * @throws IllegalStateException with any nested error
     */
    @Override
    public String decrypt(String strToDecrypt) {
        try {
            SecretKeySpec secretKeySpec = prepareSecreteKey();
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            throw new IllegalStateException("Error while decrypting", e);
        }
    }
}