package com.vip.oauth2.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.time.Duration;
import java.util.Arrays;
import java.util.UUID;

/**
 * @author echo
 * @version 1.0
 * @date 2023/3/31 11:07
 */
@Configuration
public class AuthorizationServerConfiguration {

    /**
     * 授权端点过滤器链
     * @param httpSecurity Security注入点
     * @return SecurityFilterChain
     * @throws Exception 异常
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain serverSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);

        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

        httpSecurity.exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * 配置Authorization Server实例
     * @return AuthorizationServerSettings
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                /* 客户端ID和密码 */
                .clientId("client")
                .clientSecret("{noop}secret")
                /* 授权方法 */
                .clientAuthenticationMethods(AuthenticationMethods ->
                        AuthenticationMethods.addAll(Arrays.asList(
                                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                        ClientAuthenticationMethod.CLIENT_SECRET_POST
                                )
                        )
                )
                /* 授权类型 */
                .authorizationGrantTypes(authorizationGrantTypes ->
                        authorizationGrantTypes.addAll(Arrays.asList(
                                        // 授权码
                                        AuthorizationGrantType.AUTHORIZATION_CODE,
                                        // 刷新token
                                        AuthorizationGrantType.REFRESH_TOKEN,
                                        // 客户端模式
                                        AuthorizationGrantType.CLIENT_CREDENTIALS
                                )
                        )
                )
                // 重定向url
                .redirectUris(redirectUris ->
                        redirectUris.add("https://www.baidu.com")
                )
                /* 客户端申请的作用域，也可以理解这个客户端申请访问用户的哪些信息(OidcScopes.OPENID需要用到JWT)
                 * https://www.jianshu.com/p/6a4637fed874  所以这里不想加上OidcScopes.OPENID，不然还得加上JwtGenerator
                 */
                .scope(OidcScopes.PROFILE)
                /*.scopes(scopes -> scopes.addAll(Arrays.asList(OidcScopes.OPENID, OidcScopes.PROFILE)))*/
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        // code 的有效期
                        .authorizationCodeTimeToLive(Duration.ofHours(1))
                        // accessToken 的有效期
                        .accessTokenTimeToLive(Duration.ofHours(12L))
                        // refreshToken 的有效期
                        .refreshTokenTimeToLive(Duration.ofHours(12L))
                        // 是否可重用刷新令牌
                        .reuseRefreshTokens(true)
                        .build()
                )
                // 是否需要用户确认一下客户端需要获取用户的哪些权限
                // 比如：客户端需要获取用户的 用户信息、用户照片
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build()
                )
                .build();


        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public OAuth2TokenGenerator<OAuth2Token> oAuth2TokenGenerator() {

        return new DelegatingOAuth2TokenGenerator(new OAuth2AccessTokenGenerator(), new OAuth2RefreshTokenGenerator());
    }
}
