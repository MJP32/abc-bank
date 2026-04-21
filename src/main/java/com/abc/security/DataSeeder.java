package com.abc.security;

import com.abc.domain.Account;
import com.abc.domain.Customer;
import com.abc.domain.CustomerRepository;
import com.abc.security.user.AppUser;
import com.abc.security.user.AppUserRepository;
import com.abc.security.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.EnumSet;

/**
 * Seeds demo users and bank domain data into the H2 database.
 *
 * Demo accounts (password = "password" for everyone):
 *   - alice / ROLE_USER  (also a customer named "alice")
 *   - bob   / ROLE_USER  (also a customer named "bob")
 *   - admin / ROLE_ADMIN
 */
@Configuration
public class DataSeeder {

    @Bean
    public CommandLineRunner seedDomainData(CustomerRepository customerRepo) {
        return args -> {
            if (customerRepo.count() > 0) return;

            Customer alice = new Customer("alice").openAccount(new Account(Account.SAVINGS));
            alice.openAccount(new Account(Account.CHECKING));
            alice.getAccounts().get(0).deposit(1500);

            Customer bob = new Customer("bob").openAccount(new Account(Account.MAXI_SAVINGS));
            bob.getAccounts().get(0).deposit(3000);

            customerRepo.save(alice);
            customerRepo.save(bob);
        };
    }

    @Bean
    public CommandLineRunner seedUsers(AppUserRepository users, PasswordEncoder encoder) {
        return args -> {
            if (users.count() > 0) return;
            users.save(new AppUser("alice", encoder.encode("password"), EnumSet.of(Role.USER)));
            users.save(new AppUser("bob",   encoder.encode("password"), EnumSet.of(Role.USER)));
            users.save(new AppUser("admin", encoder.encode("password"), EnumSet.of(Role.USER, Role.ADMIN)));
        };
    }
}
