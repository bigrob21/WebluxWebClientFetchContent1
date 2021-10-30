package app.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.reactive.config.CorsRegistry;
import org.springframework.web.reactive.config.ResourceHandlerRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.config.WebFluxConfigurerComposite;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

@Configuration
@EnableWebFluxSecurity
public class AppConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http.x509()
                .principalExtractor(principalExtractor())
                .and()
                .authorizeExchange()
                .anyExchange()
                .authenticated()
                .and()
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

    @Bean
    public WebFluxConfigurer enablingStaticContentCustomizer(){
        return new WebFluxConfigurerComposite() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedHeaders("*")
                        .allowedMethods("*")
                        .allowedOrigins("*");
            }

            @Override
            public void addResourceHandlers(ResourceHandlerRegistry registry) {
                registry.addResourceHandler("/public/**");
            }
        };
    }

}
