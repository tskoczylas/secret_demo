package com.prototal.usersecret.models;

import lombok.*;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PasswordChangeDto {
    private String newPassword;
}
