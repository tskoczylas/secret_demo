package com.prototal.usersecret.entity;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Builder
@Document
public class UserEntity {

    @Id
    private String userId;
    @Indexed(unique = true)
    private String username;
    private String password;
    private String email;
    private String firstName;
    private String lastName;
}
