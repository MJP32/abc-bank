package com.abc.domain;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@Transactional(readOnly = true)
public class BankService {

    private final CustomerRepository customerRepo;

    public BankService(CustomerRepository customerRepo) {
        this.customerRepo = customerRepo;
    }

    public List<Customer> getCustomers() {
        return customerRepo.findAll();
    }

    public Optional<Customer> findCustomerByName(String name) {
        return customerRepo.findByNameIgnoreCase(name);
    }

    public String customerSummary() {
        String summary = "Customer Summary";
        for (Customer c : customerRepo.findAll())
            summary += "\n - " + c.getName() + " (" + format(c.getNumberOfAccounts(), "account") + ")";
        return summary;
    }

    private String format(int number, String word) {
        return number + " " + (number == 1 ? word : word + "s");
    }

    public double totalInterestPaid() {
        double total = 0;
        for (Customer c : customerRepo.findAll())
            total += c.totalInterestEarned();
        return total;
    }

    @Transactional
    public double deposit(String customerName, double amount) {
        Customer c = customerRepo.findByNameIgnoreCase(customerName)
                .orElseThrow(() -> new IllegalArgumentException("Unknown customer: " + customerName));
        if (c.getNumberOfAccounts() == 0) {
            throw new IllegalStateException("Customer has no accounts");
        }
        Account first = c.getAccounts().get(0);
        first.deposit(amount);
        customerRepo.save(c);
        return first.sumTransactions();
    }

    @Transactional
    public Customer addCustomer(Customer customer) {
        return customerRepo.save(customer);
    }
}
