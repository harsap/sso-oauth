package com.tdi.sso.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig  extends WebSecurityConfigurerAdapter {
	
	@Autowired
	@Qualifier("dataSource")
	private DataSource dataSource;
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(11);
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication().dataSource(dataSource).passwordEncoder(passwordEncoder())
				.usersByUsernameQuery(" select username, password,is_active from auth.users a where a.username = ? and  is_active = true ")
				.authoritiesByUsernameQuery("   SELECT  usr.username , ro.name  \n"
						+ "  FROM auth.roles ro left join   \n" + "    auth.authorities ath on ro.id = ath.role_id\n"
						+ "    left join auth.user_privileges ap on ath.privilege_id = ap.privilege_id\n"
						+ "    left join auth.users usr on ap.user_id = usr.id \n" + "    where usr.username = ?  ");
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors().disable()
		.csrf().disable();

		http.authorizeRequests()
				.antMatchers(
						 "/css/**","/img/**","/oauth/authorize","/accessdenied",
						"/sign-in" ,
						 "/oauth/token",
						 "/oauth/logout",
						 "/error",
						 "/oauth/check_token")
				.permitAll().anyRequest().authenticated().and().formLogin().loginProcessingUrl("/sign-in")
				.loginPage("/sign-in").passwordParameter("passwd").usernameParameter("user")
				.defaultSuccessUrl("/", false).permitAll().and().logout()
				.logoutUrl("/logout").deleteCookies(ParameterAplikasi.JWT_TOKEN_NAME,ParameterAplikasi.JWT_USER_NAME)
				.invalidateHttpSession(true) ;
	}
}
