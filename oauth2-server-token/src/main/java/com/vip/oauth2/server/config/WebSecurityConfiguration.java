package com.vip.oauth2.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author echo
 * @version 1.0
 * @date 2023/3/31 10:57
 */
@Configuration
public class WebSecurityConfiguration {

    /**
     * <p>为什么一个项目配置了两个甚至多个 SecurityFilterChain?</p>
     * 之所以有两个 SecurityFilterChain是因为程序设计要保证职责单一，无论是底层架构还是业务代码，
     * 为此 HttpSecurity被以基于原型（prototype）的Spring Bean注入Spring IoC。
     * 针对本应用中的两条过滤器链，分别是授权服务器的过滤器链和应用安全的过滤器链，它们之间其实互相没有太多联系
     * Spring Security 默认的安全策略
     * @param httpSecurity Security注入点
     * @return SecurityFilterChain
     * @throws Exception 异常
     */
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated());
        httpSecurity.formLogin(Customizer.withDefaults());
        return httpSecurity.build();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails userDetails = User.builder()
                .username("admin")
                .password("123456")
                .passwordEncoder(passwordEncoder::encode)
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(userDetails);
    }
}
