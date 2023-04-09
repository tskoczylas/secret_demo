package com.prototal.usersecret.controlers;

import com.mongodb.MongoClientException;
import com.prototal.usersecret.entity.SecretEntity;
import com.prototal.usersecret.entity.TokenEntity;
import com.prototal.usersecret.entity.UserEntity;
import com.prototal.usersecret.models.PasswordChangeDto;
import com.prototal.usersecret.models.UserSignInDto;
import com.prototal.usersecret.repository.SecretRepository;
import com.prototal.usersecret.repository.TokenRepository;
import com.prototal.usersecret.repository.UserRepository;
import com.prototal.usersecret.services.EncryptionService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Date;
import java.util.Optional;

import static com.prototal.usersecret.security.AuthenticationFilterTest.clearAndBulidToken;
import static org.mockito.ArgumentMatchers.any;

@SpringBootTest(properties = {
        "encryption.algorithm=AES",
        "encryption.key=OXokQyZGKUpATmNSZlVqVw==",
        "jwt.token.expiryTime.milliseconds=200000"}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @LocalServerPort
    private int port;

    @MockBean
    UserRepository userRepository;

    @MockBean
    TokenRepository tokenRepository;

    @Captor
    ArgumentCaptor<String> stringArgumentCaptor;
    @Captor
    ArgumentCaptor<Date> dateArgumentCaptor;
    @Captor
    ArgumentCaptor<UserEntity> userEntityArgumentCaptor;
    @Captor
    ArgumentCaptor<SecretEntity> secretEntityArgumentCaptor;

    @Autowired
    EncryptionService encryptionService;

    @Autowired
    private TestRestTemplate restTemplate;

    final String password = "xxx2";
    final String userName = "testUser";
    @MockBean
    private SecretRepository secretRepository;

    @BeforeEach
    void loginIn() {
        Mockito.when(userRepository.findByUsername(userName)).
                thenReturn(Optional.of(UserEntity.builder().username(userName).password(new BCryptPasswordEncoder().encode(password)).build()));
        Mockito.when(tokenRepository.findByTokenId(any())).thenReturn(Optional.of(TokenEntity.builder().build()));

        String accessToken = this.restTemplate.
                getForObject("http://localhost:" + port + "/api/v1/sign-in?username=" + userName + "&password=" + password, String.class);

        clearAndBulidToken(accessToken, restTemplate);
    }


    @Test
    void testResetPasswordSuccessful() {
        //given
        PasswordChangeDto newPassword = PasswordChangeDto.builder().newPassword("newPassword").build();
        Mockito.when(userRepository.findByUsername(userName)).
                thenReturn(Optional.of(UserEntity.builder().username(userName).password(new BCryptPasswordEncoder().encode(password)).build()));

        //when
        ResponseEntity<String> stringResponseEntity = restTemplate.
                postForEntity("http://localhost:" + port + "/api/v1/reset-my-password/", newPassword, String.class);

        Mockito.verify(tokenRepository).deleteAllByUsernameAndExpiryDateAfter(stringArgumentCaptor.capture(), dateArgumentCaptor.capture());
        Mockito.verify(userRepository).save(userEntityArgumentCaptor.capture());

        String userNameToTokenDeletion = stringArgumentCaptor.getValue();
        UserEntity reSavedUser = userEntityArgumentCaptor.getValue();
        //then
        Assertions.assertEquals(userNameToTokenDeletion, userName);
        Assertions.assertEquals(reSavedUser.getUsername(), userName);
        Assertions.assertTrue(new BCryptPasswordEncoder().matches(newPassword.getNewPassword(), reSavedUser.getPassword()));
        Assertions.assertEquals(200, stringResponseEntity.getStatusCode().value());
    }

    @Test
    void testResetPasswordUnsuccessful() {
        //given
        PasswordChangeDto newPassword = PasswordChangeDto.builder().newPassword("newPassword").build();

        //when
        Mockito.doThrow(MongoClientException.class).when(userRepository).findByUsername(any());
        ResponseEntity<String> stringResponseEntity = restTemplate.
                postForEntity("http://localhost:" + port + "/api/v1/reset-my-password/", newPassword, String.class);
        //then
        Assertions.assertEquals(400, stringResponseEntity.getStatusCode().value());
    }

    @Test
    void testSignUpSuccessful() {
        //given
        String secret = "testSecret";
        UserSignInDto userSignInDto = UserSignInDto.builder().secret(secret).login(userName).password(password).build();
        //when
        ResponseEntity<String> stringResponseEntity = restTemplate.
                postForEntity("http://localhost:" + port + "/api/v1/sign-up/", userSignInDto, String.class);

        Mockito.verify(userRepository).save(userEntityArgumentCaptor.capture());
        Mockito.verify(secretRepository).save(secretEntityArgumentCaptor.capture());

        //then
        Assertions.assertEquals(200, stringResponseEntity.getStatusCode().value());
        Assertions.assertEquals(userSignInDto.getLogin(), userEntityArgumentCaptor.getValue().getUsername());
        Assertions.assertNotEquals(secretEntityArgumentCaptor.getValue().getSecret(), secret);
        Assertions.assertEquals(secret, encryptionService.decrypt(secretEntityArgumentCaptor.getValue().getSecret()));
        Assertions.assertNotEquals(password, userEntityArgumentCaptor.getValue().getPassword());
        Assertions.assertTrue(new BCryptPasswordEncoder().matches(password, userEntityArgumentCaptor.getValue().getPassword()));
    }

    @Test
    void testSignUpUnsuccessful() {
        //given
        String secret = "testSecret";
        UserSignInDto userSignInDto = UserSignInDto.builder().secret(secret).login(userName).password(password).build();
        //when
        Mockito.doThrow(MongoClientException.class).when(userRepository).save(any());
        ResponseEntity<String> stringResponseEntity = restTemplate.
                postForEntity("http://localhost:" + port + "/api/v1/sign-up/", userSignInDto, String.class);
        //then
        Assertions.assertEquals(400, stringResponseEntity.getStatusCode().value());
    }

    @Test
    void testLogOutSuccessful() {
        //given
        String secret = "testSecret";
        UserSignInDto userSignInDto = UserSignInDto.builder().secret(secret).login(userName).password(password).build();
        //when
        ResponseEntity<String> stringResponseEntity = restTemplate.
                getForEntity("http://localhost:" + port + "/api/v1/log-out", String.class);

        Mockito.verify(tokenRepository).deleteByTokenId(stringArgumentCaptor.capture());

        //then
        Assertions.assertEquals(200, stringResponseEntity.getStatusCode().value());
        Assertions.assertFalse(stringArgumentCaptor.getValue().isBlank());
    }

    @Test
    void testLogOutUnsuccessful() {
        //given
        String secret = "testSecret";
        UserSignInDto userSignInDto = UserSignInDto.builder().secret(secret).login(userName).password(password).build();
        //when
        Mockito.doThrow(MongoClientException.class).when(tokenRepository).deleteByTokenId(any());

        ResponseEntity<String> stringResponseEntity = restTemplate.
                getForEntity("http://localhost:" + port + "/api/v1/log-out", String.class);
        //then
        Assertions.assertEquals(400, stringResponseEntity.getStatusCode().value());
    }
}