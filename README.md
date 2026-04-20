ABC Bank - Spring Security learning app
========

A small Spring Boot 3.5 (Java 21) / Spring Security 6 sample built around
the existing `Bank` / `Customer` / `Account` domain (`com.abc.domain`). Use it to explore the building blocks
of Spring Security: authentication providers, password encoding, multiple
SecurityFilterChain beans, form login vs. stateless JWT, URL- and
method-level authorization, CSRF, and `MockMvc` security tests.

Run it
------

```bash
mvn spring-boot:run
# then open http://localhost:8080/
```

H2 console: `http://localhost:8080/h2-console` (JDBC URL `jdbc:h2:mem:abcbank`).

### Demo accounts (password = `password`)

| Username | Roles               |
|----------|---------------------|
| alice    | ROLE_USER           |
| bob      | ROLE_USER           |
| admin    | ROLE_USER, ROLE_ADMIN |

### Try the form-login flow (browser)

1. Visit `/dashboard` while logged out -> redirected to `/login`.
2. Log in as `alice / password` -> redirected back to `/dashboard`.
3. Visit `/admin` -> 403 (alice is not an admin).
4. Log in as `admin / password` -> `/admin` works.

### Try the JWT API flow (curl)

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password"}' | jq -r .token)

curl -s http://localhost:8080/api/me            -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:8080/api/customers     -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:8080/api/admin/report  -H "Authorization: Bearer $TOKEN"   # 403 for alice
```

What to read
------------

| Concept                       | File                                                                                                  |
|-------------------------------|-------------------------------------------------------------------------------------------------------|
| Two SecurityFilterChain beans | `src/main/java/com/abc/security/SecurityConfig.java`                                                  |
| BCrypt password encoder       | `SecurityConfig.passwordEncoder()`                                                                    |
| `UserDetailsService` over JPA | `src/main/java/com/abc/security/user/AppUserDetailsService.java`                                       |
| JWT issue + parse             | `src/main/java/com/abc/security/jwt/JwtService.java`                                                  |
| JWT auth filter               | `src/main/java/com/abc/security/jwt/JwtAuthenticationFilter.java`                                     |
| `@PreAuthorize` examples      | `src/main/java/com/abc/web/AccountApiController.java`                                                 |
| Thymeleaf + `sec:authorize`   | `src/main/resources/templates/dashboard.html`                                                         |
| `MockMvc` + `@WithMockUser`   | `src/test/java/com/abc/security/SecurityIntegrationTest.java`                                          |

Original interview brief
------------------------

This is a dummy application to be used as part of a software development interview.

instructions
--------

* Treat this code as if you owned this application, do whatever you feel is necessary to make this your own.
* There are several deliberate design, code quality and test issues that should be identified and resolved.
* Below is a list of the current features supported by the application; as well as some additional features that have been requested by the business owner.
* In order to work on this take a fork into your own GitHub area; make whatever changes you feel are necessary and when you are satisfied submit back via a pull request. See details on GitHub's [Fork & Pull](https://help.github.com/articles/using-pull-requests) model
* The project uses maven to resolve dependencies however if you want to avoid maven configuration the only external JAR that's required is junit-4.11.
* Refactor and add features (from the below list) as you see fit; there is no need to add all the features in order to "complete" the exercise. Keep in mind that code quality is the critical measure and there should be an obvious focus on testing.
* You'll notice there is no database or UI; these are not needed - the exercise deliberately avoids these requirements.
* REMEMBER: this is YOUR code, made any changes you feel are necessary.
* You're welcome to spend as much time as you like; however it's anticipated that this should take about 2 hours.

abc-bank
--------

A dummy application for a bank; should provide various functions of a retail bank.

### Current Features

* A customer can open an account
* A customer can deposit / withdraw funds from an account
* A customer can request a statement that shows transactions and totals for each of their accounts
* Different accounts have interest calculated in different ways
  * **Checking accounts** have a flat rate of 0.1%
  * **Savings accounts** have a rate of 0.1% for the first $1,000 then 0.2%
  * **Maxi-Savings accounts** have a rate of 2% for the first $1,000 then 5% for the next $1,000 then 10%
* A bank manager can get a report showing the list of customers and how many accounts they have
* A bank manager can get a report showing the total interest paid by the bank on all accounts

### Additional Features

* A customer can transfer between their accounts
* Change **Maxi-Savings accounts** to have an interest rate of 5% assuming no withdrawals in the past 10 days otherwise 0.1%
* Interest rates should accrue daily (incl. weekends), rates above are per-annum
