package com.example.PaseListaApi.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.cors() // Habilitar CORS
                .and()
                .csrf().disable() // Deshabilitar CSRF (opcional, para pruebas)
                .authorizeRequests()
                .dispatcherTypeMatchers(HttpMethod.valueOf("/v3/**")).authenticated() // Requiere autenticación para rutas específicas
                .anyRequest().permitAll() // Permitir otras rutas sin autenticación
                .and()
                .httpBasic(); // Habilitar autenticación básica (usuario/contraseña)

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200")); // Permitir Angular
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE")); // Métodos permitidos
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "*")); // Permitir encabezados, incluyendo Authorization
        configuration.setAllowCredentials(true); // Permitir envío de credenciales

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}