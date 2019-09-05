package com.tdi.sso.repository;

import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.tdi.sso.model.Roles;
import com.tdi.sso.model.Token;
import com.tdi.sso.model.UserIdentity;

@Repository
public class AuthenticationRepository {

	// private static final Logger logger =
	// LoggerFactory.getLogger(AuthenticationRepository.class);

	private static final Logger logger = LoggerFactory.getLogger(AuthenticationRepository.class);

	  

	@Autowired
	private NamedParameterJdbcTemplate jdbcTemplate;

	@Autowired
	private PasswordEncoder passwordEncoder;

	public boolean cekClientWebVsClientSecret(String clientId, String clientSecret) {
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue("clientId", clientId);
		String query = "  select   app.password as pass  " + "	    "
				+ "            from   resource.client_details app   "
				+ "	                where app.name = :clientId limit 1  ";
		try {
			String secret = jdbcTemplate.queryForObject(query, params, String.class);
			return passwordEncoder.matches(clientSecret, secret) ? true : false;
		} catch (Exception e) {
			return false;
		}

	}
	
	public boolean cekUserNamePassword(String userName, String password) {
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue("username", userName);
		String query = " SELECT   password  	FROM auth.users where  username = :username and  is_active = true  ";
		try {
			String pass = jdbcTemplate.queryForObject(query, params, String.class);
			return passwordEncoder.matches(password, pass)  ;
		} catch (Exception e) {
			return false;
		}

	}
	
	public boolean cekIsTokenValid(String kode) {
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue("kode", kode);
		String query = "  SELECT count(b.id) as banyak 	FROM oauth.access_token a  	inner join oauth.history_access_token b on b.access_id = a.auth_id \n" + 
				"	where 	b.is_logout = false and token_id = :kode  ";
		try {
			Integer banyak = jdbcTemplate.queryForObject(query, params, Integer.class);
			return banyak > 0 ? true : false;
		} catch (Exception e) {
			return false;
		}

	}
	
    @Transactional(readOnly = false)
	public String insertAccesTokenSql(Token token) {
		final String INSERT_ACCESS_TOKEN_SQL = "insert into oauth.access_token (token_id, token, auth_id, "
				+ "user_name," + " client_id, authentication, refresh_token, ip_address) \n"
				+ "values (:token_id, :token, :auth_id, :user_name, :client_id,:authentication, "
				+ ":refresh_token, :ip_address)";
		UUID uuid = UUID.randomUUID();
		final String key = uuid.toString();
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue("token_id", token.getTokenId());
		params.addValue("token", token.getTokenData().getBytes());
		params.addValue("auth_id",  key);
		params.addValue("user_name", token.getUserName());
		params.addValue("client_id", token.getClientId());
		params.addValue("authentication", "".getBytes());
		params.addValue("refresh_token", token.getRefreshToken());
		params.addValue("ip_address", token.getIpAddress());
		jdbcTemplate.update(INSERT_ACCESS_TOKEN_SQL, params);
		
		final String INSERT_HISTORY_ACCESS_TOKEN_SQL = "insert into oauth.history_access_token (id, access_id, "
				+ "ip_address, user_name, login_at, is_logout, logout_at, logout_by)\n"
				+ "VALUES (uuid_generate_v4(), :access_id, :ip_address, :user_name, now(), false, null, null);";
		params = new MapSqlParameterSource();
		params.addValue("access_id", key);
		params.addValue("ip_address", token.getIpAddress());
		params.addValue("user_name", token.getUserName()); 
		
		jdbcTemplate.update(INSERT_HISTORY_ACCESS_TOKEN_SQL, params);
		return key;
	}

	public List<String> getRedirectUrlsByClientId(String clientId, String clientSecret) {
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue("clientId", clientId);
		StringBuilder query = new StringBuilder(
				" select url.id as url_id, url.redirect_uri as redirect_uri,app.password\n"
						+ "	                from resource.client_detail_redirect_uris url \n"
						+ "	                       join resource.client_details app on url.client_id = app.id \n"
						+ "	                where app.name = :clientId   ");
		return jdbcTemplate.query(query.toString(), params, (resultSet, i) -> resultSet.getString("redirect_uri"));
	}

	public List<Roles> distinctRolesByUsername(String username) {
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue("userId", username);
		StringBuilder query = new StringBuilder(
				"select distinct role.id as role_id, role.name as role_name, role.description as role_description\n"
						+ "from auth.users u\n"
						+ "      left join auth.user_privileges granted on u.id = granted.user_id\n"
						+ "      left join auth.privileges privilege on granted.privilege_id = privilege.id\n"
						+ "      left join auth.authorities authority on authority.privilege_id = privilege.id\n"
						+ "      left join auth.roles role on authority.role_id = role.id\n"
						+ "where u.username = :userId");
		return this.jdbcTemplate.query(query.toString(), params,
				(resultSet, i) -> new Roles(resultSet.getInt("role_id"), resultSet.getString("role_name"),
						resultSet.getString("role_description")));
	}

	public List<String> distinctStringRolesByUsername(String username) {
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue("userId", username);
		StringBuilder query = new StringBuilder("select   role.name as role_name  " + " from auth.users u\n"
				+ "      left join auth.user_privileges granted on u.id = granted.user_id\n"
				+ "      left join auth.privileges privilege on granted.privilege_id = privilege.id\n"
				+ "      left join auth.authorities authority on authority.privilege_id = privilege.id\n"
				+ "      left join auth.roles role on authority.role_id = role.id\n" + "where u.username = :userId");
		return this.jdbcTemplate.query(query.toString(), params, (resultSet, i) -> resultSet.getString("role_name"));
	}

	public UserIdentity getUserProfile(String username) {
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue("username", username);
		String sql = " SELECT      a.nama_lengkap as namaLengkap, " + " '-' as alamat,  a.nipnik as nip  \n"
				+ "  FROM  auth.users b left join  auth.user_identity a  on  a.user_id = b.id  "
				+ "where b.username = :username  ";
		return jdbcTemplate.queryForObject(sql, params, new BeanPropertyRowMapper<UserIdentity>(UserIdentity.class));
	}
	
	@Transactional(readOnly = false)
	public int deleteLogoutAccesTokenSql(Token token) {
		String sql = 
				"update oauth.history_access_token  set is_logout=true , logout_at=now(), logout_by=:user_name  from oauth.access_token s \n" + 
				"where access_id  = s.auth_id and s.token_id = :token_id and  is_logout = false ";
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue("user_name", token.getUserName());
		params.addValue("token_id", token.getTokenId());
		
		jdbcTemplate.update(sql, params);
		
		sql = " DELETE FROM oauth.access_token   WHERE  token_id = :token_id ";
		params = new MapSqlParameterSource(); 
		params.addValue("token_id", token.getTokenId());
		logger.info(" ============================ "+token.toString());
		return jdbcTemplate.update(sql, params); 
	}

}
