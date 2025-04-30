package com.imt.auth.service;

import com.imt.auth.dto.LoginRequest;
import com.imt.auth.dto.RegisterRequest;
import com.imt.auth.dto.TokenResponse;
import com.imt.auth.repository.LoginAttemptRepository;
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
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final LoginAttemptRepository loginAttemptRepository;

    @Transactional
    public TokenResponse register(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("El email ya está registrado");
        }

        var user = User.builder()
                .name(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();

        userRepository.save(user);
        return TokenResponse.builder()
                .accessToken(jwtService.generateToken(user))
                .build();
    }

    @Transactional
    public TokenResponse login(LoginRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            var user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

            // Registrar intento de login exitoso
            loginAttemptRepository.registerSuccessfulLogin(user.getId(), "127.0.0.1", "Postman");

            // Revocar tokens previos
            jwtService.revokeAllUserTokens(user);

            // Generar y guardar nuevo token
            var jwtToken = jwtService.generateToken(user);
            jwtService.saveUserToken(user, jwtToken);

            return TokenResponse.builder()
                    .accessToken(jwtToken)
                    .build();

        } catch (AuthenticationException e) {
            log.error("Authentication failed for: " + request.getEmail(), e);
            throw new BadCredentialsException("Credenciales inválidas");
        }
    }
}