package app.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http.x509()
                .principalExtractor(principalExtractor())
                .and()
                .authorizeExchange()
                .anyExchange()
                .authenticated()
                .and()
                .httpBasic().disable()
                .csrf().disable()
                .build();
    }

    @Bean
    public SubjectDnX509PrincipalExtractor principalExtractor() {
        SubjectDnX509PrincipalExtractor xtractor =  new SubjectDnX509PrincipalExtractor();
        xtractor.setSubjectDnRegex("(^.*)");
        return xtractor;
    }

    @Bean
    public ReactiveUserDetailsService userDetailsService() {
        return new ReactiveUserDetailsService() {
            @Override
            public Mono<UserDetails> findByUsername(String username) {
                UserDetails user = User.builder().username(username).password(UUID.randomUUID().toString())
                        .accountExpired(false)
                        .accountLocked(false)
                        .authorities(List.of(new SimpleGrantedAuthority("USER")))
                        .credentialsExpired(false)
                        .disabled(false)
                        .build();
                return Mono.just(user);
            }
        };
    }
}
