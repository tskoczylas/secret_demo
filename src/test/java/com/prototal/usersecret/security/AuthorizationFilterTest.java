package com.prototal.usersecret.security;

import com.prototal.usersecret.entity.TokenEntity;
import com.prototal.usersecret.entity.UserEntity;
import com.prototal.usersecret.repository.TokenRepository;
import com.prototal.usersecret.repository.UserRepository;
import com.prototal.usersecret.services.EncryptionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@SpringBootTest(properties = {
        "encryption.algorithm=AES",
        "encryption.salt=OXokQyZGKUpATmNSZlVqVw==",
        "jwt.token.expiryTime.milliseconds=200000"},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthorizationFilterTest {

    @MockBean
    UserRepository userRepository;

    @MockBean
    TokenRepository tokenRepository;

    @Autowired
    EncryptionService encryptionService;

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    final String password = "xxx2";
    final String userName = "testUser";


    @BeforeEach
    public void mockUserDBResponse() {
        when(userRepository.findByUsername(userName)).
                thenReturn(Optional.of(UserEntity.builder().username(userName).password(new BCryptPasswordEncoder().encode(password)).build()));

    }

    @Test
    void successfulAuthorizationTest() {
        //given
        String accessToken = this.restTemplate.
                getForObject("http://localhost:" + port + "/api/v1/sign-in?username=testUser&password=" + password, String.class);
        //then
        assertTrue(accessToken.contains("access_token"));
    }

    @Test
    void unsuccessfulAuthorizationTestWrongPassword() {
        //given
        String response = this.restTemplate.
                getForObject("http://localhost:" + port + "/api/v1/sign-in?username=testUser&password=" + "wrongPassword", String.class);
        //then
        assertTrue(response.contains("401"));
        assertTrue(response.contains("Unauthorized"));
    }

    @Test
    void unsuccessfulAuthorizationTestToManyActiveTokens() {
        //given
        List<TokenEntity> tokenEntityList = new ArrayList<>();
        tokenEntityList.add(TokenEntity.builder().build());
        tokenEntityList.add(TokenEntity.builder().build());
        tokenEntityList.add(TokenEntity.builder().build());
        when(tokenRepository.findAllByUsernameAndExpiryDateAfter(any(), any())).thenReturn(tokenEntityList);

        //when
        String response = this.restTemplate.
                getForObject("http://localhost:" + port + "/api/v1/sign-in?username=testUser&password=" + password, String.class);

        //then
        assertTrue(response.contains("400"));
    }
}