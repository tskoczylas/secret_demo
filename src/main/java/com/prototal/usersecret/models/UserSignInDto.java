package com.prototal.usersecret.models;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Builder
public class UserSignInDto {

    private String login;
    private String password;
    private String email;
    private String firstName;
    private String lastName;
    private String secret;
}
