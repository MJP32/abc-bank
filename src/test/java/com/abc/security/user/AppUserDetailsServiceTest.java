package com.abc.security.user;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.EnumSet;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Concept under test: <b>{@link org.springframework.security.core.userdetails.UserDetailsService}</b>.
 *
 * <p>{@code UserDetailsService} is the contract that bridges your user
 * storage (here: a JPA repository) to Spring Security. The framework calls
 * {@code loadUserByUsername} during authentication. The returned
 * {@link UserDetails} carries:
 * <ul>
 *   <li>the username and (encoded) password Spring will compare against,</li>
 *   <li>a collection of granted authorities,</li>
 *   <li>account status flags (enabled, locked, expired, credentials expired).</li>
 * </ul>
 *
 * <p>Two non-obvious things this test pins down:
 * <ol>
 *   <li>Authorities are returned with the {@code ROLE_} prefix - that's what
 *       {@code hasRole('USER')} checks for. Forgetting the prefix is a
 *       very common bug.</li>
 *   <li>A missing user must throw {@link UsernameNotFoundException}. Returning
 *       {@code null} or an "empty" UserDetails would silently allow login.</li>
 * </ol>
 *
 * <p>Pure unit test - the repository is mocked.
 */
class AppUserDetailsServiceTest {

    private final AppUserRepository users = mock(AppUserRepository.class);
    private final AppUserDetailsService service = new AppUserDetailsService(users);

    @Test
    void roles_become_granted_authorities_with_role_prefix() {
        // Spring Security's hasRole('ADMIN') matches an authority literally
        // named "ROLE_ADMIN" - the prefix is conventional but mandatory.
        AppUser admin = new AppUser("admin", "{bcrypt}irrelevant",
                EnumSet.of(Role.USER, Role.ADMIN));
        when(users.findByUsername("admin")).thenReturn(Optional.of(admin));

        UserDetails details = service.loadUserByUsername("admin");

        List<String> authorityNames = details.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        assertThat(authorityNames).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
        assertThat(details.getUsername()).isEqualTo("admin");
        assertThat(details.getPassword()).isEqualTo("{bcrypt}irrelevant");
    }

    @Test
    void disabled_user_is_marked_disabled() {
        // Spring Security blocks login for users where isEnabled() == false.
        // This is how you "soft-delete" or freeze an account without removing it.
        AppUser frozen = new AppUser("alice", "{bcrypt}x", EnumSet.of(Role.USER));
        frozen.setEnabled(false);
        when(users.findByUsername("alice")).thenReturn(Optional.of(frozen));

        UserDetails details = service.loadUserByUsername("alice");

        assertThat(details.isEnabled()).isFalse();
    }

    @Test
    void unknown_username_throws_UsernameNotFoundException() {
        // Returning null or an empty UserDetails would skip the password check
        // entirely (a classic auth-bypass bug). Always throw.
        when(users.findByUsername(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.loadUserByUsername("ghost"))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("ghost");
    }
}
