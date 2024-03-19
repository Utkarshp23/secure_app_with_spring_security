package com.secure.testSecurity;

import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationEventPublisher authenticationEventPublisher) throws Exception{
        {
            http.getSharedObject(AuthenticationManagerBuilder.class)
                    .authenticationEventPublisher(authenticationEventPublisher);
        }

        var authenticationManager = new ProviderManager(new RobotAuthenticationProvider(List.of("take1","take2")));
        authenticationManager.setAuthenticationEventPublisher(authenticationEventPublisher);

        return http
                .authorizeHttpRequests(
                        authorizeConfig->{
                            authorizeConfig.requestMatchers("/").permitAll();
                            authorizeConfig.requestMatchers("/error").permitAll();
                            authorizeConfig.requestMatchers("/favicon.ico").permitAll();
                            authorizeConfig.anyRequest().authenticated();
                        }
                )
                .formLogin(withDefaults())
                .oauth2Login(withDefaults())
                .addFilterBefore(new RobotFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(new CustomAuthenticationProvider())
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService(){

        return new InMemoryUserDetailsManager(
                User.builder()
                        .username("user")
                        .password("{noop}password")
                        .authorities("ROLE_user")
                        .build()
        );
    }

    @Bean
    public ApplicationListener<AuthenticationSuccessEvent> successListener(){
        return event -> {
            System.out.println("@@@--->Successful authentication--->"+event.getAuthentication().getClass().getName()+"---->"+event.getAuthentication().getName());
        };
    }
}
