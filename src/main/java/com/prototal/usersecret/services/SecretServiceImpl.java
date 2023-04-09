package com.prototal.usersecret.services;

import com.prototal.usersecret.entity.SecretEntity;
import com.prototal.usersecret.models.SecretResponseDto;
import com.prototal.usersecret.repository.SecretRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Service use for operations with Secret
 */
@Service
@RequiredArgsConstructor
public class SecretServiceImpl implements SecretService {

    final private SecretRepository secretRepository;
    final private EncryptionService encryptionService;


    /**
     * Method to provide user secret given for username
     *
     * @param username the username
     * @return the user secret
     * @throws UsernameNotFoundException if user no fund
     */
    @Override
    public SecretResponseDto getUserSecret(String username) {
        SecretEntity secretEntity = secretRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException(username));
        String decryptedSecret = encryptionService.decrypt(secretEntity.getSecret());

        return SecretResponseDto.builder().secret(decryptedSecret).secretName(secretEntity.getSecretName()).build();
    }

}
