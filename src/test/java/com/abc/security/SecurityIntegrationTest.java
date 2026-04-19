package com.abc.security;

import com.abc.AbcBankApplication;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Black-box tests for the security wiring.
 *
 * What's covered:
 *  - Anonymous request to /api/customers -> 401 (JWT chain, stateless).
 *  - Form-login chain: anonymous /dashboard -> redirect to /login.
 *  - Method security: ROLE_USER hitting /api/admin/report -> 403.
 *  - Role-restricted URL: ROLE_USER hitting /admin -> 403.
 *  - JWT login round-trip: POST /api/auth/login then call /api/me with bearer.
 */
@SpringBootTest(classes = AbcBankApplication.class)
@AutoConfigureMockMvc
class SecurityIntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;

    @Test
    @WithAnonymousUser
    void apiRequiresAuth() throws Exception {
        mvc.perform(get("/api/customers"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithAnonymousUser
    void browserDashboardRedirectsToLogin() throws Exception {
        mvc.perform(get("/dashboard"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    @WithMockUser(username = "alice", roles = {"USER"})
    void userCannotReachAdminPage() throws Exception {
        mvc.perform(get("/admin"))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "alice", roles = {"USER"})
    void userBlockedByPreAuthorize() throws Exception {
        mvc.perform(get("/api/admin/report"))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"USER", "ADMIN"})
    void adminCanReachAdminReport() throws Exception {
        mvc.perform(get("/api/admin/report"))
            .andExpect(status().isOk());
    }

    @Test
    void jwtLoginRoundTrip() throws Exception {
        String body = """
                {"username":"alice","password":"password"}
                """;

        String response = mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        JsonNode json = mapper.readTree(response);
        String token = json.get("token").asText();

        mvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.name").value("alice"));
    }

    @Test
    void jwtLoginRejectsBadPassword() throws Exception {
        String body = """
                {"username":"alice","password":"wrong"}
                """;
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void formLoginSucceedsWithSeededUser() throws Exception {
        mvc.perform(post("/login")
                .param("username", "alice")
                .param("password", "password")
                .with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/dashboard"));
    }
}
