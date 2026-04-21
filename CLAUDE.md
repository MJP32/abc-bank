# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
mvn spring-boot:run          # start app at http://localhost:8080
mvn test                     # run all tests
mvn test -Dtest=ClassName    # run a single test class
mvn test -Dtest=ClassName#methodName  # run a single test method
mvn package                  # build JAR in target/
```

Java 21 and Maven are required. Spring Boot 3.5.0 with Spring Security 6.

## Architecture

This is a Spring Security learning application built around a legacy banking domain. It demonstrates two parallel authentication mechanisms in one app.

### Dual SecurityFilterChain design (`SecurityConfig.java`)

Two `@Order`-ed `SecurityFilterChain` beans split request handling:

1. **API chain (`@Order(1)`)** — matches `/api/**`, stateless JWT auth, CSRF disabled. `JwtAuthenticationFilter` (custom `OncePerRequestFilter`) extracts Bearer tokens and populates `SecurityContext`.
2. **Web chain (`@Order(2)`)** — everything else, session-based form login to `/login`, CSRF enabled, remember-me cookie.

Both chains share a single `DaoAuthenticationProvider` backed by `AppUserDetailsService` (JPA-based `UserDetailsService`).

### Package layout

- `com.abc.domain` — Banking model: JPA entities (`Customer`, `Account`, `Transaction`), repositories (`CustomerRepository`, `AccountRepository`), `BankService`, legacy `Bank` class (retained for JUnit 4 tests), `DateProvider`.
- `com.abc.security` — Spring Security config, `DataSeeder` (seeds demo users on startup).
- `com.abc.security.jwt` — JWT issuing/parsing (`JwtService`), auth filter, and `/api/auth/login` endpoint.
- `com.abc.security.user` — `AppUser` JPA entity, repository, `AppUserDetailsService`, `Role` enum.
- `com.abc.web` — `AccountApiController` (REST, uses `@PreAuthorize`), `PageController` (Thymeleaf views).

### Authorization layers

- **URL-level**: configured in `SecurityConfig` (`requestMatchers(...).hasRole(...)`)
- **Method-level**: `@EnableMethodSecurity` + `@PreAuthorize` with SpEL in `AccountApiController`
- **Programmatic**: checking `authentication.getName()` for owner-based access

### Data & persistence

- H2 in-memory database (`jdbc:h2:mem:abcbank`), console at `/h2-console`
- `DataSeeder` creates demo users (alice, bob, admin — all password `password`) and sample bank data on startup
- `Customer`, `Account`, and `Transaction` are JPA entities persisted to H2 via `CustomerRepository` and `AccountRepository`
- `BankService` (`@Service`) replaces the old in-memory `Bank` bean; delegates to `CustomerRepository` for all reads/writes
- Legacy `Bank.java` is retained for JUnit 4 tests but is no longer wired as a Spring bean

### Test organization

Tests are grouped by Spring Security concept, not by class-under-test:

- **Pure unit tests**: `PasswordEncoderTest`, `JwtServiceTest`, `JwtAuthenticationFilterTest`, `AppUserDetailsServiceTest`
- **Integration tests** (`@SpringBootTest` + MockMvc): `UrlAuthorizationTest`, `MethodSecurityTest`, `JwtAuthenticationFlowTest`
- **Legacy JUnit 4 tests** (vintage engine): `BankTest`, `CustomerTest`, `TransactionTest`

### JWT configuration

Properties under `app.jwt.*` in `application.yml`: `secret` (Base64-encoded HMAC key), `issuer`, `expiration-minutes`. Uses jjwt 0.12.6 library.
