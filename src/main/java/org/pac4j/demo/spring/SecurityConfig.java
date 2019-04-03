package org.pac4j.demo.spring;

import org.pac4j.core.config.Config;
import org.pac4j.springframework.security.web.CallbackFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@EnableWebFluxSecurity
public class SecurityConfig {

    @Autowired
    private Config config;

    @Bean
    public SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http)
            throws Exception {

        CallbackFilter callbackFilter = new CallbackFilter(config);
        callbackFilter.setMultiProfile(true);

        return http
                .authorizeExchange()
                .pathMatchers("/admin/info").permitAll()
                .and()
//                I couldnt add the call back filter as it is not of type WebFilter
                .addFilterAt(callbackFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }


}
