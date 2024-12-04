package com.example.PaseListaApi.config;

import javax.sql.DataSource;

import com.example.PaseListaApi.filter.JwtReqFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
public class ConfigSecurity {



    @Autowired
    @Lazy
    private JwtReqFilter jwtReqFilter;



    @Bean
    public UserDetailsManager userDetailsManager(DataSource datasource) {

        return new JdbcUserDetailsManager(datasource);
    }



    @Bean(name = "customSecurityFilterChain")

    public SecurityFilterChain customFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests( configure ->{
                    configure
                            .requestMatchers(HttpMethod.GET, "/v4/docente").hasAnyRole("Alumno" , "Profesor")
                            .requestMatchers(HttpMethod.GET, "/v4/docente/**").hasAnyRole("Alumno" , "Profesor")
                            .requestMatchers(HttpMethod.PUT, "/v4/docente/**").hasRole("Profesor")
                            .requestMatchers(HttpMethod.POST, "/v4/docente").hasRole("Profesor")

                            .requestMatchers(HttpMethod.GET, "/v3/alumnos").hasAnyRole("Alumno" , "Profesor")
                            .requestMatchers(HttpMethod.GET, "/v3/alumnos/**").hasAnyRole("Alumno" , "Profesor")
                            .requestMatchers(HttpMethod.PUT, "/v3/alumnos/**").hasRole("Profesor")
                            .requestMatchers(HttpMethod.POST, "/v3/alumnos").hasRole("Profesor")

                            .requestMatchers(HttpMethod.GET, "/v2/materias").hasAnyRole("Alumno" , "Profesor")
                            .requestMatchers(HttpMethod.GET, "/v2/materias/**").hasAnyRole("Alumno" , "Profesor")
                            .requestMatchers(HttpMethod.PUT, "/v2/materias/**").hasRole("Profesor")
                            .requestMatchers(HttpMethod.POST, "/v2/materias").hasRole("Profesor")

                            .requestMatchers(HttpMethod.GET, "/v1/grupos").hasAnyRole("Alumno" , "Profesor")
                            .requestMatchers(HttpMethod.GET, "/v1/grupos/**").hasAnyRole("Alumno" , "Profesor")
                            .requestMatchers(HttpMethod.PUT, "/v1/grupos/**").hasRole("Profesor")
                            .requestMatchers(HttpMethod.POST, "/v1/grupos").hasRole("Profesor")

                            .requestMatchers("/v1/authenticate").permitAll()
                            .requestMatchers("/v2/authenticate").permitAll()
                            .requestMatchers("/v3/authenticate").permitAll()
                            .requestMatchers("/v4/authenticate").permitAll();
                })
                .addFilterBefore(jwtReqFilter, UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(Customizer.withDefaults());

        http.csrf(csrf -> csrf.disable());
        return http.build();
    }



    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration
                                                        authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

	/*@Bean
	public InMemoryUserDetailsManager userDetailsManager() {

		UserDetails pedro = User.builder()
				.username("pedro")
				.password("{noop}pedro123")
				.roles("Empleado")
				.build();

		UserDetails hugo = User.builder()
				.username("hugo")
				.password("{noop}hugo123")
				.roles("Empleado", "Jefe")
				.build();

		UserDetails edita = User.builder()
				.username("edita")
				.password("{noop}edita123")
				.roles("Empleado", "Jefe")
				.build();

		return new InMemoryUserDetailsManager(pedro, hugo, edita);

	}*/

}