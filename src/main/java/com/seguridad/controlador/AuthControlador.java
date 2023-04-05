package com.seguridad.controlador;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.seguridad.dto.LoginDTO;
import com.seguridad.dto.RegistroDTO;
import com.seguridad.entidades.Rol;
import com.seguridad.entidades.Usuario;
import com.seguridad.seguridad.JWTAuthResponseDTO;
import com.seguridad.seguridad.JwtTokenProvider;
import com.seguridad.servicio.RolRepositorio;
import com.seguridad.servicio.UsuarioRepositorio;



@RestController
@RequestMapping("/api/auth")
public class AuthControlador {
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UsuarioRepositorio usuarioRepositorio;
	
	@Autowired
	private RolRepositorio rolRolRepositorio;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private JwtTokenProvider jwtTokenProvider;
	
	
	
	@PostMapping("/iniciarSesion")
	public ResponseEntity<JWTAuthResponseDTO> authenticateUser(@RequestBody LoginDTO loginDTO){
		
		Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginDTO.getUsernameOrEmail(), loginDTO.getPassword()));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		//obtener token jwt provider
		String token=jwtTokenProvider.generarToken(authentication);
		
		return ResponseEntity.ok(new JWTAuthResponseDTO(token));
		
	}
	
	@PostMapping("/registrar")
	public ResponseEntity<?> registrarUsuario(@RequestBody RegistroDTO registroDTO){		
		if (usuarioRepositorio.existsByUsername(registroDTO.getUsername())) {
			return new ResponseEntity<> ("El nombre de usuario ya existe", HttpStatus.BAD_REQUEST);
		}
		
		if (usuarioRepositorio.existsByEmail(registroDTO.getEmail())) {
			return new ResponseEntity<> ("El email de usuario ya existe", HttpStatus.BAD_REQUEST);
		}
		
		Usuario usuario = new Usuario();		
		usuario.setNombre(registroDTO.getNombre());
		usuario.setUsername(registroDTO.getUsername());
		usuario.setEmail(registroDTO.getEmail());
		usuario.setPassword(passwordEncoder.encode(registroDTO.getPassword()));
		
		Rol roles = rolRolRepositorio.findByNombre("ROLE_ADMIN").get();
		usuario.setRoles(Collections.singleton(roles));
		usuarioRepositorio.save(usuario);
		return new ResponseEntity<>("Usuario registrado exitoso.", HttpStatus.OK);		
	}
	

}
