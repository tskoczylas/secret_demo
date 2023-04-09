package com.prototal.usersecret.services;

import com.prototal.usersecret.models.SecretResponseDto;

public interface SecretService {
    SecretResponseDto getUserSecret(String username);


}
