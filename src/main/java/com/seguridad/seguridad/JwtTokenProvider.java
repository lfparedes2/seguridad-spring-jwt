package com.seguridad.seguridad;


import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;

@Component
public class JwtTokenProvider {

	@Value("${app.jwt-secret}")
	private String jwtSecret;
	
	@Value("${app.jwt-expiration-miliseconds}")
	private int jwtExpirationInMs;
	
	public String generarToken(Authentication authentication) {
		
		String username = authentication.getName();
		Date fechaActual = new Date();
		Date fechaExpiracion = new Date(fechaActual.getTime() + jwtExpirationInMs );
		String token= Jwts.builder().setSubject(username).setIssuedAt(new Date()).setExpiration(fechaExpiracion).signWith(SignatureAlgorithm.HS512, jwtSecret).compact();
		return token;
		
	}
	
	public String obtenerUsernameDelJWT(String token) {
		Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
		return claims.getSubject();
		
	}
	
	public boolean validarToken(String token) {
		try {
			Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
			return true;
		} catch (SignatureException ex) {
			//throw new BlogAppExcepcion(HttpStatus.BAD_REQUEST, "La cadena JWT esta vacia");
			ex.printStackTrace();
			return false;
		}
	}
}
