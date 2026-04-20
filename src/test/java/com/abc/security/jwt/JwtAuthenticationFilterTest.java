package com.abc.security.jwt;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Concept under test: <b>custom authentication filter</b>.
 *
 * <p>{@link JwtAuthenticationFilter} runs once per request (it extends
 * {@code OncePerRequestFilter}) and is registered before the standard
 * username/password filter. Its job is the same as any
 * {@code AuthenticationFilter}: <b>extract a credential, validate it, and
 * populate the {@link SecurityContextHolder}</b>. Downstream
 * authorization (URL rules, {@code @PreAuthorize}) reads from there.
 *
 * <p>Cases covered:
 * <ol>
 *   <li>Valid bearer token -> {@code SecurityContext} is populated with the
 *       subject as principal and the JWT's {@code authorities} as granted
 *       authorities.</li>
 *   <li>Invalid token (bad signature) -> context stays empty; the request
 *       continues as anonymous, which the {@code AuthenticationEntryPoint}
 *       turns into a 401 if the endpoint required auth.</li>
 *   <li>No {@code Authorization} header -> context stays empty.</li>
 *   <li>Non-Bearer scheme (e.g. {@code Basic ...}) -> filter ignores it and
 *       lets another auth filter (or the entry point) decide.</li>
 *   <li>The filter always calls {@code chain.doFilter(...)} so the request
 *       continues even when no auth was set.</li>
 * </ol>
 *
 * <p>Pure unit test using {@code MockHttpServletRequest/Response} and
 * {@code MockFilterChain}; no Spring context.
 */
class JwtAuthenticationFilterTest {

    private static final String SECRET =
            Base64.getEncoder().encodeToString("abcdefghijklmnopqrstuvwxyz123456".getBytes());

    private final JwtService jwt = new JwtService(SECRET, "abc-bank", 60);
    private final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwt);

    @BeforeEach
    void clearContext() {
        // Each test starts with a clean slate.
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void cleanupAfter() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void valid_bearer_token_populates_security_context() throws Exception {
        String token = jwt.issue("alice", List.of("ROLE_USER"));
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getName()).isEqualTo("alice");
        assertThat(auth.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER");
        // Must always continue the chain, even on success.
        verify(chain, times(1)).doFilter(req, res);
    }

    @Test
    void invalid_token_leaves_context_empty_and_continues_chain() throws Exception {
        // A garbage token must not throw or short-circuit the chain. Leaving
        // the context empty makes the request anonymous; the configured
        // AuthenticationEntryPoint then returns 401 on protected endpoints.
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer not-a-real-jwt");
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(req, res, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        // MockFilterChain records the most recent request it received.
        assertThat(chain.getRequest()).isSameAs(req);
    }

    @Test
    void missing_authorization_header_does_not_authenticate() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(req, res, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(chain.getRequest()).isSameAs(req);
    }

    @Test
    void non_bearer_scheme_is_ignored() throws Exception {
        // Filters in Spring Security are scheme-specific: a Basic credential
        // belongs to the Basic auth filter, not this one. We just pass through.
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Basic dXNlcjpwYXNz");
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(req, res, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(chain.getRequest()).isSameAs(req);
    }
}
