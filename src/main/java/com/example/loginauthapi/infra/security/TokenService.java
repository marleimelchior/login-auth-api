package com.example.loginauthapi.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.loginauthapi.domain.user.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {
    @Value("${api.security.token.secret}")
    private String secret;

    // Metodo para gerar o token
    public String generateToken(User user) {
        try {

            // Define o algoritmo de criptografia do token
            Algorithm algorithm = Algorithm.HMAC256(secret);


            // Cria o token com o email do usuário, o emissor, a data de expiração e o algoritmo de criptografia
            String token = JWT.create()
                    .withIssuer("login-auth-api") // Emissor do token
                    .withSubject(user.getEmail()) //Define o email do usuário como o assunto do token
                    .withExpiresAt(this.generateExpirationDate()) // Define a data de expiração do token
                    .sign(algorithm); // Assina o token com o algoritmo de criptografia
            return token;
        }
        catch ( JWTCreationException exception) {

            throw new RuntimeException("Erro na criação do token");
        }
    };

    // Metodo para validar o token
    public String validateToken(String token) {
        try {

            // Define o algoritmo de criptografia do token
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.require(algorithm)
                    .withIssuer("login-auth-api") //Define o algoritmo necessário para validar o token
                    .build() // Constroi o objeto de verificação do token
                    .verify(token) // Verifica o token
                    .getSubject(); // Retorna o assunto do token neste caso o email do usuário
        } catch (JWTVerificationException exception) {
            return null;
        }
    };

    // Metodo para gerar a data de expiração do token (2 horas a partir do momento da geração)
    private Instant generateExpirationDate() {
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
