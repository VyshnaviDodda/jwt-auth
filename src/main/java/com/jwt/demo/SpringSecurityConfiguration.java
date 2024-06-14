package com.jwt.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfiguration {

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final CustomJwtAuthenticationFilter customJwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint unauthorizedHandler;

    @Autowired
    public SpringSecurityConfiguration(CustomUserDetailsService userDetailsService, PasswordEncoder passwordEncoder,
                                       CustomJwtAuthenticationFilter customJwtAuthenticationFilter,
                                       JwtAuthenticationEntryPoint unauthorizedHandler) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.customJwtAuthenticationFilter = customJwtAuthenticationFilter;
        this.unauthorizedHandler = unauthorizedHandler;
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .requestMatchers("/api/admin").hasRole("ADMIN")
                .requestMatchers("/api/user").hasAnyRole("ADMIN", "USER")
                .requestMatchers("/authenticate", "/register").permitAll()
                .anyRequest().authenticated()
                .and().exceptionHandling()
                .authenticationEntryPoint(unauthorizedHandler)
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(customJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
    
    //http://localhost:8184/api/user GET
    //http://localhost:8184/api/user GET
    
    //First Checks Whether the Jwt Token Is present or not If It is present t will go to CustomJwtAuthentication filter
    //There It will fetch the jwt and do validation By Extracting All the claims(isAdmin, sub(username), Password and Create User Object 
    //And Check That UserObject with CustomUserDetailsService Having UserDetails)
    //If Username Matches It Will Create SecuritycontexHolder Object Which Says the Successful Authentication
    
    //If Token Is not There It give error Message Like Authentication IS arequired
    //Now we Have to Generate Token
    //http://localhost:8184/authenticate POST
    //{
    // "username" : "admin",
    //"password" : "admin"
    //}
    //When We Request A route It will go through the Security filter chain The routes are Authenticated
    //When We Send Username & Password (Credentials)to the Request,It will go through Authentication Filter with credentials and generate UsernamePasswordAuthentication Token Then Calls The Authenticate method of ProviderManager 
    //Which is Implenetation class of Authentication Manager, It will create Authentication Object with Credentials.
    //Which Calls DaoAuthentication Provider Which Fetches the Details Of UserDetialsService by using Username.
    //If Username Matches It will Fill the authorities(roles) as Admin OR User Based On the credentials.
    //If Username is Correct then IT REturns the USERDATAILS Object 
    //By Using That USerDetails Object It will Create Token.
    //{
    //"token": "eyJhbGciOiJIUzUxMiJ9.eyJpc0FkbWluIjp0cnVlLCJzdWIiOiJhZG1pbiIsImlhdCI6MTcxNzU2ODcyMSwiZXhwIjoxNzE3NTcwMTYxfQ.tGeJz1crrv55_SBDvZB2t1zXyGgHWsfDUaGdr_eLOrxW9cM0vND5bw5k4RT23xhxUu8VwnroeDbYHprTrl57bg"
    //}
    //Use This Token For Authentication
    
    
   
    
    
}
