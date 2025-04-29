package com.imt.auth.service;

import com.imt.auth.dto.LoginRequest;
import com.imt.auth.dto.RegisterRequest;
import com.imt.auth.dto.TokenResponse;
import com.imt.auth.repository.UserRepository;
import com.imt.auth.usuarios.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public TokenResponse register(RegisterRequest request) {
        var user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();

        userRepository.save(user);
        return TokenResponse.builder()
                .accessToken(jwtService.generateToken(user))
                .build();
    }

    public TokenResponse login(LoginRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            var user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow();

            return TokenResponse.builder()
                    .accessToken(jwtService.generateToken(user))
                    .build();

        } catch (AuthenticationException e) {
            log.error("Authentication failed for: " + request.getEmail(), e);
            throw new BadCredentialsException("Invalid credentials");
        }
    }
}