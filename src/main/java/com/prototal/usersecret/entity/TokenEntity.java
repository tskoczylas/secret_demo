package com.prototal.usersecret.entity;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

@Data
@Builder
@Document
public class TokenEntity {
    @Id
    String tokenId;
    String username;
    Date expiryDate;
}
