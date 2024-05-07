package com.example.loginauthapi.infra.security;

import com.example.loginauthapi.domain.user.User;
import com.example.loginauthapi.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    // Metodo para carregar um usuario pelo nome de usuario neste caso o email
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // busca o usuario pelo email, caso não encontre, lança uma exceção
        User user = this.repository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("Não foi possível encontrar o usuário, verifique o email informado"));
        // retorna um objeto do tipo UserDetails com o email, a senha e uma lista vazia de permissões
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), new ArrayList<>());
    }
}
