package com.example.loginauthapi.controllers;

import com.example.loginauthapi.domain.user.User;
import com.example.loginauthapi.dto.LoginRequestDTO;
import com.example.loginauthapi.dto.RegisterRequestDTO;
import com.example.loginauthapi.dto.ResponseDTO;
import com.example.loginauthapi.infra.security.TokenService;
import com.example.loginauthapi.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequestDTO body) {
        // Busca o usuario pelo email, caso não encontre, lança uma exceção, caso encontre, verifica se a senha é válida
        User user = this.repository.findByEmail(body.email()).orElseThrow(() -> new RuntimeException("Não foi possível encontrar o usuário"));
        // Verifica se a senha é valida, caso seja, gera o token e retorna o nome do usuário e o token, caso não seja, retorna um erro 400
        if(passwordEncoder.matches(body.password(), user.getPassword())) {
            String token = this.tokenService.generateToken(user);
            return ResponseEntity.ok(new ResponseDTO(user.getName(), token));
        }
        return ResponseEntity.badRequest().build();
    };

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterRequestDTO body) {
        Optional<User> user = this.repository.findByEmail(body.email());
        // se o usuario não existir, cria um novo usuario com os dados do corpo da requisição
        if(user.isEmpty()) {
            User newUser = new User();
            newUser.setPassword(passwordEncoder.encode(body.password())); //codifica a senha
            newUser.setEmail(body.email()); //seta o email
            newUser.setName(body.name()); //seta o nome
            this.repository.save(newUser); //salva o novo usuario

            // gera o token e retorna o nome do usuario e o token
            String token = this.tokenService.generateToken(newUser); 
            // retorna o nome do usuario e o token
            return ResponseEntity.ok(new ResponseDTO(newUser.getName(), token));
        }
        // se o usuario já existir, retorna uma resposta com status 400
        return ResponseEntity.badRequest().build();
    }

}
