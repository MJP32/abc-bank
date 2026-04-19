package com.abc.security;

import com.abc.security.jwt.JwtAuthenticationFilter;
import com.abc.security.jwt.JwtService;
import com.abc.security.user.AppUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Spring Security wiring.
 *
 * Two SecurityFilterChain beans are registered with explicit @Order so each
 * URL group gets the right defenses:
 *
 *  /api/**  -> stateless JWT, no CSRF, 401 on missing/invalid token
 *  /**      -> form login + sessions + CSRF for the browser UI
 *
 * @EnableMethodSecurity turns on @PreAuthorize / @PostAuthorize annotations.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * BCrypt is the default sane choice: adaptive (cost factor) and salted per-password.
     * Spring Security also ships PasswordEncoderFactories.createDelegatingPasswordEncoder()
     * which supports {bcrypt}, {scrypt}, {argon2} prefixes - useful when migrating hashes.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(AppUserDetailsService uds, PasswordEncoder encoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(uds);
        provider.setPasswordEncoder(encoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(DaoAuthenticationProvider provider) {
        return new org.springframework.security.authentication.ProviderManager(provider);
    }

    /**
     * Stateless API chain. Matched first via @Order(1).
     * - csrf disabled because there's no browser session/cookie to protect.
     * - SessionCreationPolicy.STATELESS prevents Spring from creating an HttpSession.
     * - JwtAuthenticationFilter runs before the username/password filter so a
     *   valid bearer token populates the SecurityContext.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurity(HttpSecurity http, JwtService jwtService) throws Exception {
        http
            .securityMatcher("/api/**")
            .csrf(csrf -> csrf.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            .addFilterBefore(new JwtAuthenticationFilter(jwtService),
                             UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(eh -> eh.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));

        return http.build();
    }

    /**
     * Browser/UI chain. Form login + remember-me + CSRF.
     * H2 console is permitted with frame options relaxed (dev only).
     */
    @Bean
    @Order(2)
    public SecurityFilterChain webSecurity(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/css/**", "/webjars/**", "/h2-console/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard", true)
                .permitAll())
            .logout(logout -> logout
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/?logout")
                .permitAll())
            .rememberMe(rm -> rm.key("abc-bank-remember-me-key"))
            // CSRF on by default; ignore the H2 console which posts without a token.
            .csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"))
            .headers(h -> h.frameOptions(f -> f.sameOrigin())); // H2 console uses frames

        return http.build();
    }
}
