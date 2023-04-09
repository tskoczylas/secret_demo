package com.prototal.usersecret.security;


import com.mongodb.MongoClientException;
import com.prototal.usersecret.entity.SecretEntity;
import com.prototal.usersecret.entity.TokenEntity;
import com.prototal.usersecret.entity.UserEntity;
import com.prototal.usersecret.repository.SecretRepository;
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
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;

@SpringBootTest(properties = {
        "encryption.algorithm=AES",
        "encryption.key=OXokQyZGKUpATmNSZlVqVw==",
        "jwt.token.expiryTime.milliseconds=200000"}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class AuthenticationFilterTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private EncryptionService encryptionService;

    @MockBean
    UserRepository userRepository;
    @MockBean
    SecretRepository secretRepository;

    @MockBean
    TokenRepository tokenRepository;

    final String password = "xxx2";
    final String userName = "testUser";

    final String secret = "secretTest";

    @BeforeEach
    public void mockUserDBResponse() {
        String encryptedSecret = encryptionService.encrypt(secret);

        Mockito.when(userRepository.findByUsername(userName)).
                thenReturn(Optional.of(UserEntity.builder().username(userName).password(new BCryptPasswordEncoder().encode(password)).build()));

        Mockito.when(tokenRepository.findByTokenId(any())).thenReturn(Optional.of(TokenEntity.builder().build()));
        Mockito.when(secretRepository.findByUsername(userName)).thenReturn(Optional.of(SecretEntity.builder().secret(encryptedSecret).build()));

    }

    @Test
    void successfulAuthenticationGetSecret() {
        //given
        String accessToken = this.restTemplate.
                getForObject("http://localhost:" + port + "/api/v1/sign-in?username=testUser&password=" + password, String.class);

        //when
        clearAndBulidToken(accessToken, restTemplate);

        String response = restTemplate.
                getForObject("http://localhost:" + port + "/api/v1/secret-message", String.class);
        //then
        assertTrue(response.contains(secret));

    }

    @Test
    void unauthorizedAccessBadTokenToSecretReposne403() {
        //given
        restTemplate.getRestTemplate().setInterceptors(
                Collections.singletonList((request, body, execution) -> {
                    request.getHeaders()
                            .add("Authorization", "Bearer " + "noToken");
                    return execution.execute(request, body);
                }));


        String response = restTemplate.
                getForObject("http://localhost:" + port + "/api/v1/secret-message", String.class);
        //then
        assertTrue(response.contains("401"));
    }

    @Test
    void unauthorizedAccessWrongUserToSecretReposne403() {

        String accessToken = this.restTemplate.
                getForObject("http://localhost:" + port + "/api/v1/sign-in?username=" + "noSecretUser" + "&password=" + password, String.class);
        //when
        clearAndBulidToken(accessToken, restTemplate);

        String response = restTemplate.
                getForObject("http://localhost:" + port + "/api/v1/secret-message", String.class);
        //then
        assertTrue(response.contains("401"));
    }

    public static void clearAndBulidToken(String accessToken, TestRestTemplate testRestTemplate) {
        String clearToken = accessToken.replace("access_token", "").
                replace("{", "").replace("}", "").
                replace(":", "").replace("\"", "");


        testRestTemplate.getRestTemplate().setInterceptors(
                Collections.singletonList((request, body, execution) -> {
                    request.getHeaders()
                            .add("Authorization", "Bearer " + clearToken);
                    return execution.execute(request, body);
                }));
    }

    @Test
    void getSecretErrorTest() {

        String accessToken = this.restTemplate.
                getForObject("http://localhost:" + port + "/api/v1/sign-in?username=" + userName + "&password=" + password, String.class);
        //when
        clearAndBulidToken(accessToken, restTemplate);

        Mockito.doThrow(MongoClientException.class).when(secretRepository).findByUsername(any());
        ResponseEntity<String> responseEntity = restTemplate.
                getForEntity("http://localhost:" + port + "/api/v1/secret-message", String.class);
        //then
        assertEquals(400, responseEntity.getStatusCode().value());
    }

}
