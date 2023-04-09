package com.prototal.usersecret.controlers;

import com.prototal.usersecret.models.SecretResponseDto;
import com.prototal.usersecret.services.SecretService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

/**
 * Secret Controller
 */
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@Slf4j
public class SecretController {

    private final SecretService secretService;

    /**
     * Authorize user get secret;
     * - secret is decrypting from db
     * - secret name is First Name + Last Name
     *
     * @param principal the principal
     * @return if completed 200, if error 400
     */
    @GetMapping("/secret-message")
    public ResponseEntity<Object> getSecretMessage(Principal principal) {
        try {
            SecretResponseDto userSecret = secretService.getUserSecret(principal.getName());
            return ResponseEntity.ok(userSecret);
        } catch (Exception e) {
            log.error("Error during finding user secret", e);
            return ResponseEntity.badRequest().body("Secret can not be find. Please connect support.");
        }
    }
}


