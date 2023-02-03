package org.pac4j.demo.spring;

import org.pac4j.core.config.Config;
import org.pac4j.jee.filter.CallbackFilter;
import org.pac4j.jee.filter.LogoutFilter;
import org.pac4j.jee.filter.SecurityFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig {

    @Configuration
    public static class TwitterWebSecurityConfigurationAdapter {

        @Autowired
        private Config config;

        @Bean
        public SecurityFilterChain twitterFilterChain(final HttpSecurity http) throws Exception {
            final SecurityFilter filter = new SecurityFilter(config, "TwitterClient");

            http
                    .securityMatcher("/twitter/**")
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);

            return http.build();
        }
    }

    @Configuration
    public static class CasWebSecurityConfigurationAdapter {

        @Autowired
        private Config config;

        @Bean
        public SecurityFilterChain casFilterChain(final HttpSecurity http) throws Exception {
            final SecurityFilter filter = new SecurityFilter(config, "CasClient");

            http
                    .securityMatcher("/cas/**")
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);

            return http.build();
        }
    }

    @Configuration
    public static class ProtectedWebSecurityConfigurationAdapter {

        @Autowired
        private Config config;

        @Bean
        public SecurityFilterChain protectedFilterChain(final HttpSecurity http) throws Exception {
            final SecurityFilter filter = new SecurityFilter(config);

            http
                    .securityMatcher("/protected/**")
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);

            return http.build();
        }
    }

    @Configuration
    public static class DbaWebSecurityConfigurationAdapter {

        @Autowired
        private Config config;

        @Bean
        public SecurityFilterChain dbaFilterChain(final HttpSecurity http) throws Exception {

            final SecurityFilter filter = new SecurityFilter(config, "DirectBasicAuthClient");

            http
                    .securityMatcher("/dba/**")
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);

            return http.build();
        }
    }

    @Configuration
    public static class CallbackWebSecurityConfigurationAdapter {

        @Autowired
        private Config config;

        @Bean
        public SecurityFilterChain callbackFilterChain(final HttpSecurity http) throws Exception {

            final CallbackFilter callbackFilter = new CallbackFilter(config);

            http
                    .securityMatcher("/callback*")
                    .addFilterBefore(callbackFilter, BasicAuthenticationFilter.class)
                    .csrf().disable();

            return http.build();
        }
    }

    @Configuration
    public static class LogoutWebSecurityConfigurationAdapter {

        @Autowired
        private Config config;

        @Bean
        public SecurityFilterChain logoutFilterChain(final HttpSecurity http) throws Exception {

            final LogoutFilter logoutFilter = new LogoutFilter(config, "/?defaulturlafterlogout");
            logoutFilter.setDestroySession(true);

            http
                    .securityMatcher("/pac4jLogout")
                    .addFilterBefore(logoutFilter, BasicAuthenticationFilter.class)
                    .csrf().disable();

            return http.build();
        }
    }

    @Configuration
    public static class ZeLastWebSecurityConfigurationAdapter {

        @Autowired
        private Config config;

        @Bean
        public SecurityFilterChain defaultFilterChain(final HttpSecurity http) throws Exception {

            http
                    .csrf().disable()
                    .authorizeHttpRequests()
                    .requestMatchers("/admin/**").hasRole("ADMIN")
                    .requestMatchers("/login/**").authenticated()
                    .anyRequest().permitAll()
                    .and()
                    .formLogin()
                    .loginPage("/login.html")
                    .loginProcessingUrl("/perform_login")
                    .defaultSuccessUrl("/index.html", false)
                    .failureUrl("/login.html?error=true")
                    .and()
                    .logout().logoutSuccessUrl("/");

            return http.build();
        }

        @Bean
        public InMemoryUserDetailsManager userDetailsService() {
            final UserDetails user1 = User.withDefaultPasswordEncoder()
                    .username("user")
                    .password("user")
                    .roles("USER")
                    .build();
            final UserDetails user2 = User.withDefaultPasswordEncoder()
                    .username("admin")
                    .password("admin")
                    .roles("ADMIN")
                    .build();
            return new InMemoryUserDetailsManager(user1, user2);
        }
    }
}
