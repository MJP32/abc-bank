package com.abc.security;

import com.abc.AbcBankApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Concept under test: <b>method-level security via {@code @PreAuthorize}</b>.
 *
 * <p>Enabled by {@code @EnableMethodSecurity} on
 * {@link SecurityConfig}. Spring intercepts each protected method and
 * evaluates the SpEL expression against the current {@code Authentication}
 * <i>before the method body runs</i>. If the check fails, an
 * {@link org.springframework.security.access.AccessDeniedException} is
 * thrown (translated to HTTP 403 here).
 *
 * <p>Two patterns are demonstrated:
 * <ol>
 *   <li><b>Role check:</b> {@code @PreAuthorize("hasRole('ADMIN')")} on
 *       {@code adminReport} - belt-and-braces with the URL rule.</li>
 *   <li><b>Argument check via SpEL:</b>
 *       {@code @PreAuthorize("hasRole('ADMIN') or #req.customer == authentication.name")}
 *       on {@code deposit} - a user can only deposit into their own account
 *       unless they are an admin. SpEL can reference method args by name
 *       ({@code #req}) and the principal ({@code authentication}).</li>
 * </ol>
 *
 * <p>Why a separate test class? URL-rule failures vs. method-security
 * failures look identical (HTTP 403) but come from different layers.
 * Splitting them out keeps the cause-and-effect obvious and means a
 * regression in one layer doesn't disguise the other still working.
 */
@SpringBootTest(classes = AbcBankApplication.class)
@AutoConfigureMockMvc
class MethodSecurityTest {

    @Autowired MockMvc mvc;

    @Test
    @WithMockUser(username = "alice", roles = {"USER"})
    void user_blocked_by_hasRole_ADMIN_method_check() throws Exception {
        // /api/admin/report has both a URL rule AND @PreAuthorize - either
        // alone would block this. Exercises the @PreAuthorize role check.
        mvc.perform(get("/api/admin/report"))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"USER", "ADMIN"})
    void admin_passes_hasRole_ADMIN_method_check() throws Exception {
        mvc.perform(get("/api/admin/report"))
            .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "alice", roles = {"USER"})
    void user_can_deposit_into_their_own_account_via_spel_owner_check() throws Exception {
        // The SpEL expression #req.customer == authentication.name evaluates
        // against the deserialized request body. alice depositing as "alice"
        // passes; the actual deposit succeeds and the new balance is returned.
        mvc.perform(post("/api/deposit")
                .with(jwtCsrfDisabled())
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"customer":"alice","amount":50}
                        """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.balance").exists());
    }

    @Test
    @WithMockUser(username = "alice", roles = {"USER"})
    void user_cannot_deposit_into_someone_elses_account() throws Exception {
        // alice tries to deposit as "bob" - SpEL check fails before the
        // controller body runs, so we get 403 and the deposit never happens.
        mvc.perform(post("/api/deposit")
                .with(jwtCsrfDisabled())
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"customer":"bob","amount":50}
                        """))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"USER", "ADMIN"})
    void admin_can_deposit_into_any_account_via_spel_role_branch() throws Exception {
        // Same SpEL: hasRole('ADMIN') OR owner-match. The role branch is
        // what passes here even though admin != bob.
        mvc.perform(post("/api/deposit")
                .with(jwtCsrfDisabled())
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"customer":"bob","amount":50}
                        """))
            .andExpect(status().isOk());
    }

    /**
     * The /api/** chain has CSRF disabled (stateless). MockMvc still expects
     * a CSRF post-processor on POSTs by default; this no-op makes the intent
     * explicit so readers don't think we're "bypassing" anything.
     */
    private static org.springframework.test.web.servlet.request.RequestPostProcessor jwtCsrfDisabled() {
        return request -> request;
    }
}
