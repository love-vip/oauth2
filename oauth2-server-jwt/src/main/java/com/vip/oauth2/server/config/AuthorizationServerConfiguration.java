package com.vip.oauth2.server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.SneakyThrows;
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
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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

        httpSecurity.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

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
                // 客户端申请的作用域，也可以理解这个客户端申请访问用户的哪些信息
                .scopes(scopes -> scopes.addAll(Arrays.asList(OidcScopes.OPENID, OidcScopes.PROFILE)))
                .tokenSettings(TokenSettings.builder()
                        //accessTokenFormat: 访问令牌格式，支持OAuth2TokenFormat.SELF_CONTAINED（自包含的令牌使用受保护的、有时间限制的数据结构，例如JWT）；
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
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
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    @SneakyThrows
    public JWKSource<SecurityContext> jwkSource() {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

}
