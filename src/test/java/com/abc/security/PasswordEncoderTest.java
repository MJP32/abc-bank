package com.abc.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Concept under test: <b>password encoding</b>.
 *
 * <p>Spring Security never compares plaintext passwords. Instead, the
 * configured {@link PasswordEncoder} hashes the user-supplied password and
 * compares it to the stored hash. This test pins down the BCrypt encoder's
 * behavior we rely on in {@code SecurityConfig.passwordEncoder()}.
 *
 * <p>Three properties matter for learners:
 * <ul>
 *   <li>{@link PasswordEncoder#encode} produces a hash, not the plaintext.</li>
 *   <li>{@link PasswordEncoder#matches} returns true only for the original
 *       plaintext.</li>
 *   <li>BCrypt salts each call, so the same plaintext produces a different
 *       hash every time. This defeats rainbow-table attacks.</li>
 * </ul>
 *
 * <p>This is a pure unit test - no Spring context is loaded.
 */
class PasswordEncoderTest {

    private final PasswordEncoder encoder = new BCryptPasswordEncoder();

    @Test
    void encoded_password_is_not_the_plaintext() {
        // The output must NOT equal the input - if it does, you forgot to encode.
        String hash = encoder.encode("hunter2");

        assertThat(hash).isNotEqualTo("hunter2");
        // BCrypt hashes always start with the version prefix $2a$, $2b$, or $2y$.
        assertThat(hash).matches("^\\$2[aby]\\$.*");
    }

    @Test
    void matches_returns_true_for_correct_password() {
        // What the DaoAuthenticationProvider does internally: encode-then-match.
        String hash = encoder.encode("hunter2");

        assertThat(encoder.matches("hunter2", hash)).isTrue();
    }

    @Test
    void matches_returns_false_for_wrong_password() {
        String hash = encoder.encode("hunter2");

        assertThat(encoder.matches("wrong", hash)).isFalse();
    }

    @Test
    void same_plaintext_produces_different_hashes_due_to_per_call_salt() {
        // BCrypt embeds a random salt in each hash. Storing salted hashes means
        // an attacker who steals the database cannot precompute hashes (rainbow
        // tables) and cannot tell which users share a password.
        String hash1 = encoder.encode("hunter2");
        String hash2 = encoder.encode("hunter2");

        assertThat(hash1).isNotEqualTo(hash2);
        assertThat(encoder.matches("hunter2", hash1)).isTrue();
        assertThat(encoder.matches("hunter2", hash2)).isTrue();
    }
}
