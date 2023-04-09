package com.prototal.usersecret.security;

import com.prototal.usersecret.repository.TokenRepository;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static io.swagger.v3.oas.annotations.enums.SecuritySchemeIn.HEADER;
import static io.swagger.v3.oas.annotations.enums.SecuritySchemeType.HTTP;


/**
 * Spring Security Configuration Class
 */
@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    @Value("${jwt.token.encryption.key}")
    private String tokenEncKey;

    @Value("${jwt.token.expiryTime.milliseconds}")
    private Long tokenExpiryTime;


    /**
     * Authentication configuration defining UserDetailsService(User implementation for Auth) and defining Password Encoder
     *
     * @param auth the auth
     * @throws Exception the exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    /**
     * Main Security Config Defining all filters and permissions .
     *
     * @param http the http
     * @throws Exception the exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManagerBean(), tokenRepository, tokenEncKey, tokenExpiryTime);
        authenticationFilter.setFilterProcessesUrl("/api/v1/sign-in");

        http.cors();
        http.csrf().disable().authorizeHttpRequests();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.authorizeHttpRequests().antMatchers(HttpMethod.POST, "/api/v1/sign-up").permitAll();
        http.authorizeHttpRequests().antMatchers(HttpMethod.POST, "/api/v1/login").permitAll();

        http.authorizeHttpRequests().antMatchers(HttpMethod.GET, "/api/v1/secret-message").authenticated();
        http.authorizeHttpRequests().antMatchers(HttpMethod.GET, "/api/v1/*").authenticated();

        http.addFilter(authenticationFilter);
        http.addFilterBefore(new AuthorizationFilter(tokenEncKey, tokenRepository), UsernamePasswordAuthenticationFilter.class);

    }

    /**
     * Authentication manager bean is being used to define custom AuthenticationFilter
     *
     * @return the authentication manager
     * @throws Exception the exception
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * Password encoder settings
     *
     * @return the password encoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
