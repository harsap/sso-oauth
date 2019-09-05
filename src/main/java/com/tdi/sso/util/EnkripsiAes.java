package com.tdi.sso.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Base64Utils;

import com.tdi.sso.config.ParameterAplikasi;

public class EnkripsiAes {
	private static final Logger logger = LoggerFactory.getLogger(EnkripsiAes.class);

	public static InetAddress getClientIpAddr(HttpServletRequest request) {
		String ip = request.getHeader("X-Forwarded-For");
		if (StringUtils.isEmpty(ip) || StringUtils.equalsIgnoreCase("unknown", ip)) {
			ip = request.getHeader("Proxy-Client-IP");
		}
		if (StringUtils.isEmpty(ip) || StringUtils.equalsIgnoreCase("unknown", ip)) {
			ip = request.getHeader("WL-Proxy-Client-IP");
		}
		if (StringUtils.isEmpty(ip) || StringUtils.equalsIgnoreCase("unknown", ip)) {
			ip = request.getHeader("HTTP_CLIENT_IP");
		}
		if (StringUtils.isEmpty(ip) || StringUtils.equalsIgnoreCase("unknown", ip)) {
			ip = request.getHeader("HTTP_X_FORWARDED_FOR");
		}
		if (StringUtils.isEmpty(ip) || StringUtils.equalsIgnoreCase("unknown", ip)) {
			ip = request.getRemoteAddr();
		}
		try {
			return InetAddress.getByName(ip);
		} catch (UnknownHostException e) {
			return null;
		}
	}

	public static String decrypt(String strToDecrypt) {
		try {
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(ParameterAplikasi.SKEY.toCharArray(), ParameterAplikasi.SALT.getBytes(),
					65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
			return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
		} catch (Exception e) {
			logger.info("Error while decrypting: " + e.toString());
		}
		return null;
	}

	public static String encrypt(String strToEncrypt) {
		try {
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(ParameterAplikasi.SKEY.toCharArray(), ParameterAplikasi.SALT.getBytes(),
					65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
			return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
		} catch (Exception e) {
			logger.info("Error while encrypting: " + e.toString());
		}
		return null;
	}

	public static void main(String[] args) {
		/*String originalString = "yayyeyyay";

		String encryptedString = EnkripsiAes.encrypt(originalString);
		String decryptedString = EnkripsiAes.decrypt(encryptedString);

		System.out.println(Base64Utils.encodeToString(
				"78glwPGwfBOP5MucHmyVx8EQIUpqNf74479EJc1tie1OzRJJrf+k2JUskwSx7H6bVprh2ax4nToMhgI5IhrTWioTd4H05zNVBlvEx4hAQ+0="
						.getBytes()));*/

		/*
		 * logger.info(originalString); logger.info(encryptedString);
		 * logger.info(decryptedString);
		 */
	}
}
