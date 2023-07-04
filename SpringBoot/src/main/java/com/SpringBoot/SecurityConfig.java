package com.SpringBoot.main;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.inventory.main.service.MyUserService;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	public MyUserService myUserService;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.inMemoryAuthentication()
//		.withUser("msdhoni@incedo.com").password(getEncoder().encode("csk")).authorities("ADMIN")
//		.and()
//		.withUser("vkholi@incedo.com").password(getEncoder().encode("rcb")).authorities("USER");
		
		auth.authenticationProvider(getProvider());
	}
	
	private AuthenticationProvider getProvider() {
		DaoAuthenticationProvider dao = new DaoAuthenticationProvider();
		dao.setPasswordEncoder(getEncoder());
		dao.setUserDetailsService(myUserService);
		return dao;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers(HttpMethod.POST, "/inward/add/{productId}/{godownId}/{supplierId}").hasAuthority("ADMIN")
		.antMatchers(HttpMethod.POST, "/customer/add").permitAll()
		.antMatchers(HttpMethod.POST, "/product/add").hasAnyAuthority("ADMIN", "USER")
		.antMatchers(HttpMethod.POST, "/supplier/add").authenticated()
		.antMatchers(HttpMethod.GET, "/user/login").authenticated()
		.anyRequest().permitAll()
		.and()
		.httpBasic()
		.and()
		.csrf().disable();
	}
	
	@Bean
	public PasswordEncoder getEncoder() {
		return new BCryptPasswordEncoder();
	}
}
