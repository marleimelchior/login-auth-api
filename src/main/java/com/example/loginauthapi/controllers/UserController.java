package com.example.loginauthapi.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    // Metodo para retornar uma mensagem de sucesso, indicando que o usuario está logado
    @GetMapping
    public ResponseEntity<String> getUser() {
        return ResponseEntity.ok("Usuario Logado com Sucesso!!!");
    }

}
