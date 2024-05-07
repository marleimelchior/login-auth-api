package com.example.loginauthapi.infra.security;

import com.example.loginauthapi.domain.user.User;
import com.example.loginauthapi.repositories.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@RequiredArgsConstructor
@Component
public class SecurityFilter  extends OncePerRequestFilter {

    @Autowired
    TokenService tokenService;

    @Autowired
     UserRepository userRepository;

     // metodo para filtrar as requisições, recuperar o token, validar o token e setar o usuario autenticado no contexto de segurança
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var token = recoverToken(request); //recupera o token
        var login = tokenService.validateToken(token);
        if(login != null) { //se o login for diferente de nulo, seta o usuario autenticado no contexto de segurança
            //busca o usuario pelo email, caso não encontre, lança uma exceção
            User user = userRepository.findByEmail(login).orElseThrow(() -> new RuntimeException("Usuário não encontrado"));
            //seta o usuario autenticado no contexto de segurança, com o email, a senha e a permissão de usuário
            var authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
            var authentication = new UsernamePasswordAuthenticationToken(user, null, authorities);
            //seta o contexto de segurança com a autenticação
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }

    //  metodo para recuperar o token do cabeçalho da requisição
    private String recoverToken(HttpServletRequest request) {
        var authHeader = request.getHeader("Authorization"); //recupera o cabeçalho de autorização
        if(authHeader == null) return null; //se o cabeçalho for nulo, retorna nulo
        return authHeader.replace("Bearer ", ""); //retorna o token sem o prefixo Bearer
     }

}
