package com.prototal.usersecret.services;

public interface EncryptionService {

    String encrypt(String strToEncrypt);
    String decrypt(String strToDecrypt);
}
