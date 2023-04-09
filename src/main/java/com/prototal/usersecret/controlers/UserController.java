package com.prototal.usersecret.controlers;

import com.prototal.usersecret.models.PasswordChangeDto;
import com.prototal.usersecret.models.UserSignInDto;
import com.prototal.usersecret.services.TokenService;
import com.prototal.usersecret.services.UserServiceImp;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.*;

/**
 * Controller to handle user request
 */
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@Slf4j
public class UserController {


    private final UserServiceImp userService;
    private final TokenService tokenService;

    /**
     * Sign up - no authenticate and authorized public access controller:
     * - user can sign up and save controller
     * - username bust be unique
     *
     * @param userSignInDto the user sign in dto
     * @return if completed 200, if error 400
     */
    @PostMapping("/sign-up")
    public ResponseEntity<String> signUp(@RequestBody UserSignInDto userSignInDto) {
        try {
            userService.signUp(userSignInDto);
            return ResponseEntity.ok("User has been saved");
        } catch (Exception e) {
            log.error("Error during user saving. User ID {}", userSignInDto.getLogin());
            return ResponseEntity.badRequest().body("User can not be saved. You might try to save user that already exist. Please connect support.");
        }
    }

    /**
     * Log out:
     * - removing current token id from id
     * - user can not authorize current token
     * - user have to sin-in to get new token
     *
     * @return if completed 200, if error 400
     */
    @GetMapping("/log-out")
    public ResponseEntity<String> logOut() {
        try {
            tokenService.logOut();
            return ResponseEntity.ok("You have been log-out. Token has been removed");
        } catch (Exception e) {
            log.error("Error during deleting user token.", e);
            return ResponseEntity.badRequest().body("We could not log you out. Please contact support.");
        }
    }

    /**
     * Reset password:
     * - User have to be authorized
     * - Password is being changed
     * - All current tokens is being removed
     * - User needs to re-sign in with new password to get new token
     *
     * @param passwordChangeDto the password change dto
     * @return if completed 200, if error 400
     */
    @PostMapping("/reset-my-password")
    public ResponseEntity<String> resetPassword(@RequestBody PasswordChangeDto passwordChangeDto) {
        try {
            tokenService.resetPassword(passwordChangeDto.getNewPassword());
            return ResponseEntity.ok("You password has been reset. You need to get new token to re login");
        } catch (Exception e) {
            log.error("Error during password changing.", e);
            return ResponseEntity.badRequest().body("We could not change your passsword. Please contact support.");
        }
    }
}


