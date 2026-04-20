package com.abc.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Concept under test: <b>stateless authentication via JWT</b>.
 *
 * <p>A JWT is a compact, signed, self-contained credential: the server does
 * not store session state. Security depends entirely on the signature, the
 * issuer claim, and the expiration claim all being verified on every request.
 *
 * <p>This test exercises {@link JwtService} directly (no Spring context) and
 * pins down the three checks Spring Security's auth filter relies on:
 * <ol>
 *   <li>A token signed with the service's key round-trips correctly.</li>
 *   <li>A token signed with a <i>different</i> key is rejected - otherwise
 *       anyone could mint tokens.</li>
 *   <li>A token with a <i>different</i> issuer is rejected - otherwise a
 *       token from another system could be accepted here.</li>
 *   <li>An expired token is rejected - otherwise stolen tokens live forever.</li>
 * </ol>
 */
class JwtServiceTest {

    // Base64-encoded 32-byte HMAC key - required size for HS256.
    private static final String KEY_A =
            Base64.getEncoder().encodeToString("abcdefghijklmnopqrstuvwxyz123456".getBytes());
    private static final String KEY_B =
            Base64.getEncoder().encodeToString("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456".getBytes());

    private final JwtService service = new JwtService(KEY_A, "abc-bank", 60);

    @Test
    void round_trip_preserves_subject_and_authorities() {
        // Issue a token, then parse it back. The subject is the username and
        // the "authorities" claim carries the roles - both are how downstream
        // filters populate the SecurityContext.
        String token = service.issue("alice", List.of("ROLE_USER"));

        Jws<Claims> parsed = service.parse(token);
        Claims claims = parsed.getPayload();

        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.get("authorities", List.class)).containsExactly("ROLE_USER");
        assertThat(claims.getIssuer()).isEqualTo("abc-bank");
    }

    @Test
    void token_signed_with_different_key_is_rejected() {
        // Attacker mints a token with their own key. If we didn't verify the
        // signature we'd trust it. jjwt's verifyWith() throws on mismatch.
        JwtService attackerService = new JwtService(KEY_B, "abc-bank", 60);
        String forgedToken = attackerService.issue("alice", List.of("ROLE_ADMIN"));

        assertThatThrownBy(() -> service.parse(forgedToken))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void token_with_wrong_issuer_is_rejected() {
        // Cross-tenant safety: a token minted for a different product must not
        // authenticate here. The service's parser is configured with
        // requireIssuer("abc-bank"), so any other iss value throws.
        JwtService otherSystem = new JwtService(KEY_A, "some-other-app", 60);
        String foreignToken = otherSystem.issue("alice", List.of("ROLE_USER"));

        assertThatThrownBy(() -> service.parse(foreignToken))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void expired_token_is_rejected() throws InterruptedException {
        // A 0-minute TTL means exp == iat; jjwt's clock-skew check still marks
        // this expired once we give it a beat. This is what protects against
        // stolen / replayed tokens living forever.
        JwtService shortLived = new JwtService(KEY_A, "abc-bank", 0);
        String token = shortLived.issue("alice", List.of("ROLE_USER"));

        Thread.sleep(1_100);

        assertThatThrownBy(() -> shortLived.parse(token))
                .isInstanceOf(ExpiredJwtException.class);
    }
}
