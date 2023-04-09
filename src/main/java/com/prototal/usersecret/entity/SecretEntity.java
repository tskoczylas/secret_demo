package com.prototal.usersecret.entity;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Builder
@Document
public class SecretEntity {
    @Id
    String secretId;
    @Indexed(unique = true)
    String username;
    String secretName;
    String secret;
}
