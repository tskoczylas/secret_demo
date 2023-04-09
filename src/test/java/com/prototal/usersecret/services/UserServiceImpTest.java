package com.prototal.usersecret.services;

import com.prototal.usersecret.entity.SecretEntity;
import com.prototal.usersecret.entity.UserEntity;
import com.prototal.usersecret.models.UserSignInDto;
import com.prototal.usersecret.repository.SecretRepository;
import com.prototal.usersecret.repository.UserRepository;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.mockito.ArgumentMatchers.any;

@ExtendWith(MockitoExtension.class)
class UserServiceImpTest {

    @Mock
    UserRepository userRepository;
    @Mock
    SecretRepository secretRepository;
    @Mock
    EncryptionService encryptionService;

    @InjectMocks
    UserServiceImp userServiceImp;

    @Captor
    ArgumentCaptor<UserEntity> saveUserCaptor;
    @Captor
    ArgumentCaptor<SecretEntity> saveSecretCaptor;

    @Test
    void signUpShouldSaveUserAndSecret() {
        //given
        String password = "testPassword";
        new BCryptPasswordEncoder().encode(password);
        Mockito.when(encryptionService.encrypt(any())).thenReturn("secret");
        userServiceImp.signUp(UserSignInDto.builder().login("testLogin").password(password).build());
        //when
        Mockito.verify(userRepository).save(saveUserCaptor.capture());
        Mockito.verify(secretRepository).save(saveSecretCaptor.capture());

        SecretEntity captureSecret = saveSecretCaptor.getValue();
        UserEntity captureUser = saveUserCaptor.getValue();
        //then
        Assertions.assertTrue(new BCryptPasswordEncoder().matches(password, captureUser.getPassword()));
        Assertions.assertEquals("testLogin", captureUser.getUsername());
        Assertions.assertEquals("secret", captureSecret.getSecret());
    }
}