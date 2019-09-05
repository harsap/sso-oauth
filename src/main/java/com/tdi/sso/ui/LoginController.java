package com.tdi.sso.ui;

import java.net.URI;
import java.security.Principal;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.Base64Utils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.github.jscookie.javacookie.Cookies;
import com.github.jscookie.javacookie.Cookies.Attributes;
import com.github.jscookie.javacookie.Expiration;
import com.tdi.sso.config.ParameterAplikasi;
import com.tdi.sso.model.Client;
import com.tdi.sso.model.Token;
import com.tdi.sso.model.User;
import com.tdi.sso.repository.AuthenticationRepository;
import com.tdi.sso.util.EnkripsiAes;
import com.tdi.sso.util.JWTUtil;

import io.jsonwebtoken.Claims;

@Controller
public class LoginController {

	private static final Logger logger = LoggerFactory.getLogger(LoginController.class);

	@Autowired
	private JWTUtil jwtUtil;

	@Autowired
	private AuthenticationRepository authenticationRepository;

	@RequestMapping("/")
	public ResponseEntity<Void> home(HttpServletRequest req, HttpServletResponse resp) {
		Principal principal = req.getUserPrincipal();
		String userName = principal.getName();
		req.setAttribute("user", userName);
		Client client = (Client) req.getSession().getAttribute("client");
		req.getSession().removeAttribute("client");
		String ecrypt = doEnkripsiAes(principal, client);
		Cookies cookies = Cookies.initFromServlet(req, resp);
		cookies.set(ParameterAplikasi.JWT_TOKEN_NAME, ecrypt, Attributes.empty().expires(Expiration.days(1)));
		cookies.set(ParameterAplikasi.JWT_USER_NAME, EnkripsiAes.encrypt(userName),
				Attributes.empty().expires(Expiration.days(1)));
		Token tken = new Token();
		tken.setTokenId(ecrypt);
		tken.setTokenData(ecrypt);
		tken.setIpAddress(EnkripsiAes.getClientIpAddr(req).getHostAddress());
		tken.setUserName(principal.getName());
		tken.setClientId(client.getClientId());
		authenticationRepository.insertAccesTokenSql(tken);

		return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(client.getRedirectUrl() + "?code=" + ecrypt))
				.build();

	}

	@RequestMapping("/sign-in")
	public String login() {
		return "login";
	}

	@RequestMapping("/accessdenied")
	public String accessDenied() {
		return "accessdenied";
	}

	@RequestMapping("/beranda")
	public String beranda() {
		return "secure";
	}

	@ResponseBody
	@RequestMapping(value = "/oauth/check_token", method = { RequestMethod.GET, RequestMethod.POST })
	public ResponseEntity<Claims> decodeToken(@RequestHeader Map<String, Object> params, @RequestParam String token) {
		String headerAuth = (String) params.get(HttpHeaders.AUTHORIZATION);
		String credentials = headerAuth.substring("Basic".length()).trim();
		logger.info(" <<<<<<<<<       ++++++++++XXXXXXXXX params  " + params.toString());
		if (StringUtils.isNotEmpty(credentials)) {
			final boolean statusToken = jwtUtil.validateToken(token);
			if (StringUtils.isNotEmpty(token) && statusToken) {
				return ResponseEntity.status(HttpStatus.OK).body(jwtUtil.getAllClaimsFromToken(token));
			} else {
				return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
			}

		} else {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
		}

	}

	@CrossOrigin
	@ResponseBody
	@RequestMapping(value = "/oauth/token", method = { RequestMethod.GET, RequestMethod.POST })
	public ResponseEntity<Map<String, String>> generateToken(@RequestHeader Map<String, Object> params,
			@RequestParam String code) {
		final String headerAuth = (String) params.get(HttpHeaders.AUTHORIZATION);
		// final String grantType = (String)
		// params.get(ParameterAplikasi.GRANT_TYPE_HEADER);
		Map<String, String> outAkhir = new HashMap<String, String>();

		if (headerAuth != null) {
			String credentials = headerAuth.substring("Basic".length()).trim();
			Map<String, String> mapOut = null;

			if (StringUtils.equalsIgnoreCase(code, "password")) {
				mapOut = passwordFlow(params, credentials, jwtUtil, authenticationRepository);

			} else {
				mapOut = authCodeFlow(credentials, code, jwtUtil, authenticationRepository);
			}

			if (Objects.equals(mapOut.get("status"), "405")) {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOut);
			} else {
				return ResponseEntity.status(HttpStatus.OK).body(mapOut);
			}

		} else {
			outAkhir.put("status", "405");
			outAkhir.put("error_description", "Anda tidak berhak akses halaman ini!");
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(outAkhir);
		}

	}

	@RequestMapping(value = "/oauth/authorize", method = { RequestMethod.GET, RequestMethod.POST })
	public String authorize(HttpServletRequest req, HttpServletResponse resp) {
		boolean status = false;
		boolean statusEksis = false;
		String clientId = req.getParameter("client_id");
		String clientSecret = req.getParameter("client_secret");
		String redirectUrl = req.getParameter("redirect_uri");
		Client client = new Client(clientId, clientSecret, redirectUrl);
		String decodeKode[] = null;
		boolean cekPass = authenticationRepository.cekClientWebVsClientSecret(clientId, clientSecret);
		String kuki = null;
		List<String> listurl = authenticationRepository.getRedirectUrlsByClientId(clientId, clientSecret);
		if (listurl != null && listurl.size() > 0 && cekPass) {
			status = listurl.stream().anyMatch(str -> str.trim().equalsIgnoreCase(redirectUrl));

			req.getSession().setAttribute("client", client);
			Cookies cookies = Cookies.initFromServlet(req, resp);
			kuki = cookies.get(ParameterAplikasi.JWT_TOKEN_NAME);

			if (kuki != null && StringUtils.isNotEmpty(kuki)) {
				boolean isTokenOk = authenticationRepository.cekIsTokenValid(kuki);
				if (isTokenOk) {
					decodeKode = doDekripAes(kuki);
					if (Objects.equals(clientId, decodeKode[1]) && Objects.equals(clientSecret, decodeKode[2])) {
						statusEksis = true;
					}
				}

			}
		}

		if (status) {
			if (statusEksis && ArrayUtils.isNotEmpty(decodeKode)) {
				String redirek = "redirect:" + redirectUrl + "?code=" + kuki;

				return redirek;
			} else {
				return "redirect:/sign-in";
			}
		} else {
			return "redirect:/accessdenied";
		}

	}

	@RequestMapping(value = "/oauth/logout", method = { RequestMethod.GET, RequestMethod.POST })
	public String logout(@RequestBody Map<String, Object> codeMap, @RequestParam String code, HttpServletRequest req,
			HttpServletResponse resp) {
		Cookies cookies = Cookies.initFromServlet(req, resp);

		cookies.remove(ParameterAplikasi.JWT_TOKEN_NAME);
		cookies.remove(ParameterAplikasi.JWT_USER_NAME);

		Token tken = new Token();
		tken.setTokenId(code);
		String[] decodeKode = doDekripAes(code);
		tken.setUserName(decodeKode[0]);
		authenticationRepository.deleteLogoutAccesTokenSql(tken);

		return "redirect:/sign-in";
	}

//=================================================================================================================
	private Map<String, String> passwordFlow(Map<String, Object> params, final String credentials,
			final JWTUtil jwtUtil, final AuthenticationRepository authenticationRepository) {
		Map<String, String> outAkhir = new HashMap<String, String>();
		Map<String, String> paramHeader = getAuthHeaderBasic(credentials);
		final String clientId = paramHeader.get("CLIENT_ID");
		final String secret = paramHeader.get("CLIENT_SECRET");
		boolean cekPass = authenticationRepository.cekClientWebVsClientSecret(clientId, secret);

		final String useName = (String) params.get(ParameterAplikasi.USERNAME_PARAM_HEADER);
		final String password = (String) params.get(ParameterAplikasi.PASSWORD_PARAM_HEADER);
		boolean isUserValid = authenticationRepository.cekUserNamePassword(useName, password);

		if (cekPass && isUserValid) {
			User user = new User(useName, authenticationRepository.getUserProfile(useName));
			List<String> rolesList = authenticationRepository.distinctStringRolesByUsername(useName);
			outAkhir.put("status", "200");
			outAkhir.put("access_token", jwtUtil.generateToken(user, rolesList, clientId, secret));
		} else {
			outAkhir.put("status", "405");
			outAkhir.put("error_description", "User Or Password invalid! ");

		}

		return outAkhir;
	}

	private Map<String, String> authCodeFlow(final String credentials, final String code, final JWTUtil jwtUtil,
			final AuthenticationRepository authenticationRepository) {
		Map<String, String> paramHeader = getAuthHeaderBasic(credentials);
		Map<String, String> outAkhir = new HashMap<String, String>();

		String decodeKode[] = doDekripAes(code);
		final String clientId = paramHeader.get("CLIENT_ID");
		final String secret = paramHeader.get("CLIENT_SECRET");
		long expTime = Long.parseLong(decodeKode[3]);
		boolean statusExp = sudahExpire(new Timestamp(expTime));
		if (Objects.equals(clientId, decodeKode[1]) && Objects.equals(secret, decodeKode[2]) && !statusExp) {
			boolean isTokenOk = authenticationRepository.cekIsTokenValid(code);

			if (isTokenOk) {
				User user = new User(decodeKode[0], authenticationRepository.getUserProfile(decodeKode[0]));
				List<String> rolesList = authenticationRepository.distinctStringRolesByUsername(decodeKode[0]);
				outAkhir.put("status", "200");
				outAkhir.put("access_token", jwtUtil.generateToken(user, rolesList, clientId, secret));

			} else {
				outAkhir.put("status", "405");
				outAkhir.put("error_description", "Token invalid! ");

			}

		} else {
			outAkhir.put("status", "405");
			outAkhir.put("error_description", "Anda tidak berhak akses halaman ini!");

		}
		return outAkhir;
	}

	private String[] doDekripAes(String kode) {
		String code = new String(Base64Utils.decodeFromString(kode));
		String decodeKodeStr = EnkripsiAes.decrypt(code);
		return StringUtils.split(decodeKodeStr, "|");
	}

	private String doEnkripsiAes(Principal principal, Client client) {
		return Base64Utils
				.encodeToString(
						EnkripsiAes
								.encrypt(new StringBuilder(principal.getName()).append("|").append(client.getClientId())
										.append("|").append(client.getClientSecret()).append("|")
										.append(DateUtils.addHours(new Timestamp(System.currentTimeMillis()), 1)
												.getTime())
										.append("|").append(UUID.randomUUID().toString()).toString())
								.getBytes());
	}

	private boolean sudahExpire(Timestamp waktu) {
		Timestamp now = new Timestamp(System.currentTimeMillis());
		return now.after(waktu);// sudah expires
	}

	private Map<String, String> getAuthHeaderBasic(String param) {
		String hasil = new String(Base64Utils.decodeFromString(param));

		String[] output = StringUtils.split(hasil, ":");
		Map<String, String> outAkhir = new HashMap<String, String>();
		outAkhir.put("CLIENT_ID", output[0]);
		outAkhir.put("CLIENT_SECRET", output[1]);
		return outAkhir;

	}
}
