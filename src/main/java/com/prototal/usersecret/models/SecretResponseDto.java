package com.prototal.usersecret.models;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SecretResponseDto {

    String secretName;
    String secret;
}
