package com.abc.web;

import com.abc.domain.Account;
import com.abc.domain.Bank;
import com.abc.domain.Customer;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Sample API showing different authorization styles:
 *
 *  - URL-rule auth: SecurityConfig already restricts /api/admin/** to ADMIN.
 *  - Annotation auth: @PreAuthorize on individual methods, evaluated by SpEL.
 *  - Programmatic checks: comparing authentication.getName() to the resource owner
 *    (here: the customer's name) so users can only see their own accounts.
 *
 * The Bank/Customer/Account types are the original domain classes from the repo.
 */
@RestController
@RequestMapping("/api")
public class AccountApiController {

    private final Bank bank;

    public AccountApiController(Bank bank) {
        this.bank = bank;
    }

    public record CustomerSummary(String name, int accounts, double totalInterest) {}
    public record DepositRequest(@NotBlank String customer, @Positive double amount) {}

    @GetMapping("/me")
    public Map<String, Object> me(Authentication auth) {
        return Map.of(
                "name", auth.getName(),
                "authorities", auth.getAuthorities().stream().map(Object::toString).toList());
    }

    /**
     * Any authenticated user may list customers. In a real bank you'd scope
     * this further; kept simple for the learning example.
     */
    @GetMapping("/customers")
    public List<CustomerSummary> listCustomers() {
        return bank.getCustomers().stream()
                .map(c -> new CustomerSummary(c.getName(), c.getNumberOfAccounts(), c.totalInterestEarned()))
                .toList();
    }

    /**
     * Owner-or-admin check done programmatically. SpEL alternative would be:
     *   @PreAuthorize("hasRole('ADMIN') or #name == authentication.name")
     */
    @GetMapping("/customers/{name}")
    public CustomerSummary getCustomer(@PathVariable String name, Authentication auth) {
        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        if (!isAdmin && !auth.getName().equalsIgnoreCase(name)) {
            throw new AccessDeniedException("You may only view your own account");
        }
        Customer c = findOrThrow(name);
        return new CustomerSummary(c.getName(), c.getNumberOfAccounts(), c.totalInterestEarned());
    }

    /**
     * Demonstrates @PreAuthorize with SpEL referencing a method argument.
     * The expression is evaluated before the method runs, so an unauthorized
     * caller never reaches the body.
     */
    @PostMapping("/deposit")
    @PreAuthorize("hasRole('ADMIN') or #req.customer == authentication.name")
    public Map<String, Object> deposit(@RequestBody DepositRequest req) {
        Customer c = findOrThrow(req.customer());
        Account first = c.getNumberOfAccounts() == 0 ? null : c.getAccounts().get(0);
        if (first == null) {
            throw new IllegalStateException("Customer has no accounts");
        }
        first.deposit(req.amount());
        return Map.of("balance", first.sumTransactions());
    }

    /** Admin-only endpoint - covered by both URL rule and method annotation. */
    @GetMapping("/admin/report")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminReport() {
        return bank.customerSummary();
    }

    private Customer findOrThrow(String name) {
        return bank.getCustomers().stream()
                .filter(c -> c.getName().equalsIgnoreCase(name))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown customer: " + name));
    }
}
