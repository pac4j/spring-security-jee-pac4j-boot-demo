package org.pac4j.demo.spring;

import org.pac4j.core.config.Config;
import org.pac4j.springframework.security.web.CallbackFilter;
import org.pac4j.springframework.security.web.LogoutFilter;
import org.pac4j.springframework.security.web.Pac4jEntryPoint;
import org.pac4j.springframework.security.web.SecurityFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig {

    @Configuration
    @Order(1)
    public static class FacebookWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        protected void configure(final HttpSecurity http) throws Exception {

            final SecurityFilter filter = new SecurityFilter(config, "FacebookClient");
            filter.setMatchers("excludedPath");

            http
                    .antMatcher("/facebook/**")
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
        }
    }

    @Configuration
    @Order(2)
    public static class FacebookAdminWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        protected void configure(final HttpSecurity http) throws Exception {

            final SecurityFilter filter = new SecurityFilter(config, "FacebookClient", "admin");

            http
                    .antMatcher("/facebookadmin/**")
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
        }
    }

    @Configuration
    @Order(3)
    public static class FacebookCustomWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        protected void configure(final HttpSecurity http) throws Exception {

            final SecurityFilter filter = new SecurityFilter(config, "FacebookClient", "custom");

            http
                    .antMatcher("/facebookcustom/**")
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
        }
    }

    @Configuration
    @Order(4)
    public static class TwitterWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        protected void configure(final HttpSecurity http) throws Exception {

            final SecurityFilter filter = new SecurityFilter(config, "TwitterClient,FacebookClient");

            http
                    .antMatcher("/twitter/**")
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
        }
    }

    @Configuration
    @Order(5)
    public static class FormWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        protected void configure(final HttpSecurity http) throws Exception {

            final SecurityFilter filter = new SecurityFilter(config, "DirectBasicAuthClient,AnonymousClient");

            http
                    .antMatcher("/form/**")
                        .authorizeRequests().anyRequest().authenticated()
                    .and()
                    .exceptionHandling().authenticationEntryPoint(new Pac4jEntryPoint(config, "FormClient"))
                    .and()
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
        }
    }

    @Configuration
    @Order(6)
    public static class BasicAuthWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        protected void configure(final HttpSecurity http) throws Exception {

            final SecurityFilter filter = new SecurityFilter(config, "IndirectBasicAuthClient");

            http
                    .antMatcher("/basicauth/**")
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
        }
    }

    @Configuration
    @Order(7)
    public static class Saml2WebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        protected void configure(final HttpSecurity http) throws Exception {

            final SecurityFilter filter = new SecurityFilter(config, "Saml2Client");

            http
                    .antMatcher("/saml/**")
                    .authorizeRequests()
                        .antMatchers("/saml/admin.html").hasRole("ADMIN")
                        .antMatchers("/saml/**").authenticated()
                    .and()
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
        }
    }

    @Configuration
    @Order(8)
    public static class GoogleOidcWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        protected void configure(final HttpSecurity http) throws Exception {

            final SecurityFilter filter = new SecurityFilter(config, "GoogleOidcClient");

            http
                    .antMatcher("/oidc/**")
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
        }
    }

    @Configuration
    @Order(9)
    public static class GoogleWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        protected void configure(final HttpSecurity http) throws Exception {

            final SecurityFilter filter = new SecurityFilter(config, "Google2Client");

            http
                    .antMatcher("/google/**")
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
        }
    }

    @Configuration
    @Order(10)
    public static class ProtectedWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        protected void configure(final HttpSecurity http) throws Exception {

            final SecurityFilter filter = new SecurityFilter(config);

            http
                    .antMatcher("/protected/**")
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
        }
    }

    @Configuration
    @Order(11)
    public static class JwtWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        protected void configure(final HttpSecurity http) throws Exception {

            final SecurityFilter filter = new SecurityFilter(config, "ParameterClient");

            http
                    .antMatcher("/rest-jwt/**")
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
        }
    }

    @Configuration
    @Order(12)
    public static class DbaWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        protected void configure(final HttpSecurity http) throws Exception {

            final SecurityFilter filter = new SecurityFilter(config, "DirectBasicAuthClient,ParameterClient");

            http
                    .antMatcher("/dba/**")
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
        }
    }

    @Configuration
    @Order(15)
    public static class DefaultWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        protected void configure(final HttpSecurity http) throws Exception {

            final CallbackFilter callbackFilter = new CallbackFilter(config);
            callbackFilter.setMultiProfile(true);

            final LogoutFilter logoutFilter = new LogoutFilter(config, "/?defaulturlafterlogout");
            logoutFilter.setDestroySession(true);
            logoutFilter.setSuffix("/pac4jLogout");

            final LogoutFilter centralLogoutFilter = new LogoutFilter(config, "http://localhost:8080/?defaulturlafterlogoutafteridp");
            centralLogoutFilter.setLocalLogout(false);
            centralLogoutFilter.setCentralLogout(true);
            centralLogoutFilter.setLogoutUrlPattern("http://localhost:8080/.*");
            centralLogoutFilter.setSuffix("/pac4jCentralLogout");

            http
                    .authorizeRequests()
                        .antMatchers("/cas/**").authenticated()
                        .anyRequest().permitAll()
                    .and()
                    .exceptionHandling().authenticationEntryPoint(new Pac4jEntryPoint(config, "CasClient"))
                    .and()
                    .addFilterBefore(callbackFilter, BasicAuthenticationFilter.class)
                    .addFilterBefore(logoutFilter, CallbackFilter.class)
                    .addFilterAfter(centralLogoutFilter, CallbackFilter.class)
                    .csrf().disable()
                    .logout()
                        .logoutSuccessUrl("/");
        }
    }
}
