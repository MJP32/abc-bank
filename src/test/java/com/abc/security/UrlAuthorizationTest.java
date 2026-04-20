package com.abc.security;

import com.abc.AbcBankApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Concept under test: <b>URL-based authorization on the browser chain</b>.
 *
 * <p>This is the {@code authorizeHttpRequests(...)} block in
 * {@link SecurityConfig#webSecurity}. Each test maps a single rule to a
 * single observable behavior so it's obvious which configuration line is
 * being exercised.
 *
 * <p>Topics covered:
 * <ul>
 *   <li>Public paths ({@code /}, {@code /login}) - no auth required.</li>
 *   <li>Protected paths -> redirect to {@code /login} when anonymous.</li>
 *   <li>Role-restricted paths (i.e. {@code /admin/**}) -> 403 for users
 *       without the right role.</li>
 *   <li>Form-login success / failure semantics.</li>
 *   <li>CSRF protection on state-changing browser POSTs.</li>
 * </ul>
 *
 * <p>Uses {@code @SpringBootTest} to load the real {@code SecurityFilterChain}
 * and {@code @AutoConfigureMockMvc} to drive it without starting an HTTP
 * server. {@code @WithMockUser} bypasses the password check so each test can
 * focus on authorization rather than authentication.
 */
@SpringBootTest(classes = AbcBankApplication.class)
@AutoConfigureMockMvc
class UrlAuthorizationTest {

    @Autowired MockMvc mvc;

    @Test
    @WithAnonymousUser
    void public_pages_are_reachable_without_auth() throws Exception {
        // The "/" and "/login" patterns are listed as permitAll in
        // SecurityConfig.webSecurity. Anonymous GETs return 200.
        mvc.perform(get("/")).andExpect(status().isOk());
        mvc.perform(get("/login")).andExpect(status().isOk());
    }

    @Test
    @WithAnonymousUser
    void protected_page_redirects_anonymous_user_to_login() throws Exception {
        // Default form-login behavior: an unauthenticated request to a
        // protected URL is redirected to the loginPage (/login).
        mvc.perform(get("/dashboard"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    @WithMockUser(username = "alice", roles = {"USER"})
    void user_with_USER_role_can_reach_dashboard() throws Exception {
        // Once authenticated the same URL is reachable. @WithMockUser injects
        // an Authentication into the SecurityContext for this test.
        mvc.perform(get("/dashboard")).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "alice", roles = {"USER"})
    void user_without_ADMIN_role_is_forbidden_from_admin_page() throws Exception {
        // /admin/** requires hasRole('ADMIN'). A logged-in non-admin gets 403,
        // not a redirect - they're authenticated, just not authorized.
        mvc.perform(get("/admin")).andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"USER", "ADMIN"})
    void user_with_ADMIN_role_can_reach_admin_page() throws Exception {
        mvc.perform(get("/admin")).andExpect(status().isOk());
    }

    @Test
    void form_login_with_valid_credentials_redirects_to_dashboard() throws Exception {
        // Spring Security's form-login filter accepts username/password as
        // form params and redirects to defaultSuccessUrl on success. The
        // .with(csrf()) helper adds a valid CSRF token.
        mvc.perform(post("/login")
                .param("username", "alice")
                .param("password", "password")
                .with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/dashboard"));
    }

    @Test
    void form_login_with_bad_password_redirects_to_login_with_error_flag() throws Exception {
        mvc.perform(post("/login")
                .param("username", "alice")
                .param("password", "WRONG")
                .with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void post_to_browser_endpoint_without_csrf_is_forbidden() throws Exception {
        // Spring Security enables CSRF protection by default on the browser
        // chain. A POST without a token (here: the logout POST) is rejected
        // with 403 - this is what protects users from cross-site form posts.
        mvc.perform(post("/logout"))
            .andExpect(status().isForbidden());
    }

    @Test
    void post_with_csrf_token_succeeds() throws Exception {
        // Same endpoint, same method - just adding a valid token makes it work.
        mvc.perform(post("/logout").with(csrf()))
            .andExpect(status().is3xxRedirection());
    }
}
