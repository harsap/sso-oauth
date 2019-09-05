package com.tdi.sso.util;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.tdi.sso.config.ParameterAplikasi;
import com.tdi.sso.model.User;
import com.tdi.sso.ui.LoginController;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JWTUtil implements java.io.Serializable {
	private static final long serialVersionUID = 1L;

	private static final Logger logger = LoggerFactory.getLogger(LoginController.class);

	public Claims getAllClaimsFromToken(String token) {
		return Jwts.parser().setSigningKey(Base64.getEncoder().encodeToString(ParameterAplikasi.JWT_SECRET.getBytes()))
				.parseClaimsJws(token).getBody();
	}

	public String getUsernameFromToken(String token) {
		return getAllClaimsFromToken(token).getSubject();
	}

	public Date getExpirationDateFromToken(String token) {
		return getAllClaimsFromToken(token).getExpiration();
	}

	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	public String generateToken(User user,String clientId,String secret) {
		Map<String, Object> claims = new HashMap<>();
		claims.put("authorities", user.getListRoles());
		claims.put("active", true/*user.isActive()*/);
		claims.put("userid", user.getUserIdentity());
		claims.put("client_id", clientId);
		claims.put("client_secret", secret);
		return doGenerateToken(claims, user.getUsername());
	}
	
	public String generateToken(User user,List<String> roles,String clientId,String secret) {
		Map<String, Object> claims = new HashMap<>();
		claims.put("authorities", roles);
		claims.put("active", true /*user.isActive()*/);
		claims.put("userid", user.getUserIdentity());
		claims.put("username", user.getUsername());
		claims.put("client_id", clientId);
		claims.put("client_secret", secret);
		return doGenerateToken(claims, user.getUsername());
	}

	private String doGenerateToken(Map<String, Object> claims, String username) {
		Long expirationTimeLong = ParameterAplikasi.JWT_EXP;
		final Date createdDate = new Date();
		final Date expirationDate = new Date(createdDate.getTime() + expirationTimeLong * 1000);
		return Jwts.builder().addClaims( claims).setSubject(username).setIssuedAt(createdDate)
				.setExpiration(expirationDate).signWith(SignatureAlgorithm.HS512,
						Base64.getEncoder().encodeToString(ParameterAplikasi.JWT_SECRET.getBytes())).compact();
	}

	public Boolean validateToken(String token) {
		return !isTokenExpired(token);
	}
}
