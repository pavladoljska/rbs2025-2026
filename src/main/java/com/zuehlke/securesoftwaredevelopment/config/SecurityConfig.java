package com.zuehlke.securesoftwaredevelopment.config;

import com.zuehlke.securesoftwaredevelopment.domain.User;
import com.zuehlke.securesoftwaredevelopment.service.UserDetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private static final Logger LOG = LoggerFactory.getLogger(SecurityConfig.class);
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(SecurityConfig.class);

    private final DatabaseAuthenticationProvider databaseAuthenticationProvider;
    private final UserDetailsServiceImpl userDetailsService;

    public SecurityConfig(DatabaseAuthenticationProvider databaseAuthenticationProvider, UserDetailsServiceImpl userDetailsService) {
        this.databaseAuthenticationProvider = databaseAuthenticationProvider;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/**").authenticated()
                .and()
                .formLogin()
                .authenticationDetailsSource(request -> request.getParameter("totp"))
                .loginPage("/login")
                .loginProcessingUrl("/perform-login")
                .defaultSuccessUrl("/hotels")
                .failureUrl("/login?error")
                .and()
                .logout()
                .logoutSuccessUrl("/login")
                .addLogoutHandler((request, response, authentication) -> {
                    if (authentication != null && authentication.getPrincipal() instanceof User) {
                        User user = (User) authentication.getPrincipal();
                        LOG.info("User logged out: userId={}, username='{}'", user.getId(), user.getUsername());
                        auditLogger.audit("User logged out: username='" + user.getUsername() + "'");
                    }
                })
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID");

        // We need this one in order to access h2-console
        http.headers().frameOptions().sameOrigin();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(databaseAuthenticationProvider);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new PlainTextPasswordEncoder();
    }

}
