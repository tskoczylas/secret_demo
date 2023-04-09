package com.prototal.usersecret.services;

public interface TokenService {

    void logOut();
    void resetPassword(String newPassword);
}
