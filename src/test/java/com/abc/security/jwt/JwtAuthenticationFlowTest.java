package com.abc.security.jwt;

import com.abc.AbcBankApplication;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Concept under test: <b>end-to-end stateless JWT flow on {@code /api/**}</b>.
 *
 * <p>Walks through the same sequence a non-browser client (mobile app, curl,
 * service-to-service) would perform:
 * <ol>
 *   <li>{@code POST /api/auth/login} with username + password.</li>
 *   <li>Receive a signed JWT in the response.</li>
 *   <li>Send subsequent requests with {@code Authorization: Bearer <token>}.</li>
 *   <li>The {@code JwtAuthenticationFilter} validates the token and
 *       populates the {@code SecurityContext} so URL rules and
 *       {@code @PreAuthorize} can authorize the request.</li>
 * </ol>
 *
 * <p>Why a separate test from {@link JwtAuthenticationFilterTest}? That one
 * unit-tests the filter in isolation. <i>This</i> one verifies that the
 * filter is wired into the {@code SecurityFilterChain} for {@code /api/**}
 * and cooperates with the rest of the stack (auth manager, encoder,
 * UserDetailsService, entry point).
 *
 * <p>Why not also use {@code @WithMockUser}? Because the whole point is to
 * exercise real JWT issuance and verification - a mock user would skip both.
 */
@SpringBootTest(classes = AbcBankApplication.class)
@AutoConfigureMockMvc
class JwtAuthenticationFlowTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;

    @Test
    void anonymous_request_to_api_returns_401_not_a_redirect() throws Exception {
        // The /api chain uses HttpStatusEntryPoint(UNAUTHORIZED) instead of
        // a redirect to /login. Stateless APIs expect 401, not HTML.
        mvc.perform(get("/api/customers"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void login_with_valid_credentials_returns_a_bearer_token() throws Exception {
        // The auth controller calls AuthenticationManager.authenticate(...),
        // which delegates to DaoAuthenticationProvider -> UserDetailsService
        // -> BCryptPasswordEncoder.matches. On success it issues a JWT.
        String body = mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"username":"alice","password":"password"}
                        """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.tokenType").value("Bearer"))
            .andExpect(jsonPath("$.token").isNotEmpty())
            .andReturn().getResponse().getContentAsString();

        JsonNode json = mapper.readTree(body);
        // Sanity check on JWT shape: header.payload.signature.
        String token = json.get("token").asText();
        assertHasThreeDotSeparatedSegments(token);
    }

    @Test
    void login_with_bad_password_returns_401_and_no_token() throws Exception {
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"username":"alice","password":"WRONG"}
                        """))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("invalid_credentials"));
    }

    @Test
    void issued_bearer_token_authenticates_subsequent_request() throws Exception {
        // Round-trip the credential: log in, then use the token to call /api/me.
        String token = obtainToken("alice", "password");

        mvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.name").value("alice"))
            .andExpect(jsonPath("$.authorities[0]").value("ROLE_USER"));
    }

    @Test
    void malformed_bearer_token_results_in_401() throws Exception {
        // The filter swallows the JwtException, leaves the context empty, and
        // the entry point converts the missing auth into 401. That means a
        // single line in JwtAuthenticationFilter is what saves us from
        // returning a 500 to the client.
        mvc.perform(get("/api/me").header("Authorization", "Bearer not-a-real-jwt"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void bearer_token_authorities_drive_method_security() throws Exception {
        // alice is ROLE_USER, so /api/admin/report (protected by both URL rule
        // and @PreAuthorize) must return 403 even with a valid token. This
        // proves the JWT's authorities claim is being honored, not ignored.
        String token = obtainToken("alice", "password");

        mvc.perform(get("/api/admin/report").header("Authorization", "Bearer " + token))
            .andExpect(status().isForbidden());
    }

    @Test
    void admin_bearer_token_passes_admin_only_endpoint() throws Exception {
        String token = obtainToken("admin", "password");

        mvc.perform(get("/api/admin/report").header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());
    }

    private String obtainToken(String username, String password) throws Exception {
        String body = mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        return mapper.readTree(body).get("token").asText();
    }

    private static void assertHasThreeDotSeparatedSegments(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new AssertionError("Expected JWT shape header.payload.signature, got: " + token);
        }
    }
}
