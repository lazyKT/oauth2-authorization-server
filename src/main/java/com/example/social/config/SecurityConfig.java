package com.example.social.config;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
public class SecurityConfig {

    // Reference
    // https://github.com/rwinch/spring-enterprise-authorization-server/blob/main/authorization-server/src/main/java/com/example/authorizationserver/SecurityConfig.java

    // http://127.0.0.1:9000/oauth2/authorize?response_type=code&client_id=321887139601-vc3eo5m1d49trc1dghol10r2oi90lmrs.apps.googleusercontent.com&scope=openid%20profile%20email&redirect_uri=https://springone.io/authorized&code_challenge=UaVlinitZBLiAVioZYcbZJxWN56C-RcHc2skvwzUZ1w&code_challenge_method=S256
    // http://127.0.0.1:9000/oauth2/token?client_id=321887139601-vc3eo5m1d49trc1dghol10r2oi90lmrs.apps.googleusercontent.com&redirect_uri=https://springone.io/authorized&grant_type=authorization_code&code=kWqfCLTseraaML3o89Z32tiaKicfXUN148yCH5jciVO_ftL1nNJipInjTiqyMREro7w0ZAYAjROWLOZqiMpHoFURzIQbImxLD1OxrwWosHdKgBII145WOzMuLTYF1Ptn&code_verifier=tNEvflOrbH9xT5cSZ7V3BMIVi0BWKMGPAnrqI97tsxM&scope=openid%20profile%20email

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerFilterChain (HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .authorizationEndpoint(authEndPoint -> authEndPoint.consentPage("/oauth2/consent"))
            .oidc(Customizer.withDefaults()); // Enable OpenID Connect 1.0

        http.exceptionHandling(
            // Redirect to the OAuth2.0 login endpoint (below filter chain) when not authenticated
            // from the authorization endpoint
            (exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            )
        )
        .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }


//    @Bean
//    public MvcRequestMatcher.Builder mvc (HandlerMappingIntrospector introspector) {
//        return new MvcRequestMatcher.Builder(introspector).servletPath("/mvc");
//    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain (
        HttpSecurity http
    ) throws Exception {
        http.authorizeHttpRequests(
                (authorize) -> authorize
                        .requestMatchers("/login", "/error").permitAll()
                        .anyRequest().authenticated()
        )
        // OAuth2 login handles the redirect to the OAuth 2.0 Login endpoint
        // from the authorization server filter chain above
        .formLogin(formLogin -> formLogin.loginPage("/login"))
        .oauth2Login(oauth2Login -> oauth2Login.loginPage("/login"));
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService () {
        UserDetails user = User.builder().username("user").password("user").build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings () {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository () {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .redirectUri("https://springone.io/authorized")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.EMAIL)
                .scope(OidcScopes.PROFILE)
                .tokenSettings(
                    TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofDays(1))
                        .build()
                )
                .clientSettings(
                        ClientSettings.builder().requireAuthorizationConsent(true).build()
                )
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        kg.initialize(2048);
        KeyPair keyPair = kg.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet set = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(set);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
        return (context) -> {
            context.getClaims().claim("google-oauth2", "google-oauth2");
        };
    }

    @Bean
    public OAuth2AuthorizationConsentService auth2AuthorizationConsentService () {
        return new InMemoryOAuth2AuthorizationConsentService();
    }
}
