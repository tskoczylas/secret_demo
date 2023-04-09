package com.prototal.usersecret.services;

import com.prototal.usersecret.models.UserSignInDto;

public interface UserService {
    void signUp(UserSignInDto userSignInDto);
}
