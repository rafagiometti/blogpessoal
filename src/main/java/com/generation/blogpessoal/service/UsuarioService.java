package com.generation.blogpessoal.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.generation.blogpessoal.model.Usuario;
import com.generation.blogpessoal.model.UsuarioLogin;
import com.generation.blogpessoal.repository.UsuarioRepository;
import com.generation.blogpessoal.security.JwtService;

import jakarta.validation.Valid;

@Service
public class UsuarioService {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private JwtService jwtService;

    // Cadastrar novo usuário
    public Optional<Usuario> cadastrarUsuario(Usuario usuario) {

        if (usuarioRepository.findByUsuario(usuario.getUsuario()).isPresent())
            return Optional.empty();

        usuario.setSenha(criptografarSenha(usuario.getSenha()));

        return Optional.of(usuarioRepository.save(usuario));
    }

    // Atualizar usuário
    public Optional<Usuario> atualizarUsuario(@Valid Usuario usuario) {
        if (usuario.getId() == null || !usuarioRepository.existsById(usuario.getId()))
            return Optional.empty();

        usuario.setSenha(criptografarSenha(usuario.getSenha()));

        return Optional.of(usuarioRepository.save(usuario));
    }

    // Autenticar login
    public Optional<UsuarioLogin> autenticarUsuario(Optional<UsuarioLogin> usuarioLogin) {

        Optional<Usuario> usuario = usuarioRepository.findByUsuario(usuarioLogin.get().getUsuario());

        if (usuario.isPresent()) {
            if (compararSenhas(usuarioLogin.get().getSenha(), usuario.get().getSenha())) {

                String token = jwtService.generateToken(usuario.get().getUsuario());

                UsuarioLogin login = new UsuarioLogin();
                login.setId(usuario.get().getId());
                login.setNome(usuario.get().getNome());
                login.setUsuario(usuario.get().getUsuario());
                login.setToken(token);
                login.setSenha(null); // Nunca retorne a senha

                return Optional.of(login);
            }
        }

        return Optional.empty();
    }

    // Buscar usuário por ID
    public Optional<Usuario> getById(Long id) {
        return usuarioRepository.findById(id);
    }

    // Listar todos os usuários
    public List<Usuario> getAll() {
        return usuarioRepository.findAll();
    }

    // ------------------------------
    // MÉTODOS AUXILIARES
    // ------------------------------

    private String criptografarSenha(String senha) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        return encoder.encode(senha);
    }

    private boolean compararSenhas(String senhaDigitada, String senhaBanco) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        return encoder.matches(senhaDigitada, senhaBanco);
    }
}
