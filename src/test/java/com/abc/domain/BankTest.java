package com.abc.domain;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class BankTest {
	private static final double DOUBLE_DELTA = 1e-15;

	@Test
	public void customerSummary() {
		Bank bank = new Bank();
		Customer john = new Customer("John");
		john.openAccount(new Account(Account.CHECKING));
		bank.addCustomer(john);

		assertEquals("Customer Summary\n - John (1 account)", bank.customerSummary());
	}

	@Test
	public void checkingAccount() {
		Bank bank = new Bank();
		Account checkingAccount = new Account(Account.CHECKING);
		Customer bill = new Customer("Bill").openAccount(checkingAccount);
		bank.addCustomer(bill);
		checkingAccount.deposit(100.0);

		assertEquals(0.1, bank.totalInterestPaid(), DOUBLE_DELTA);
	}

	@Test
	public void savings_account() {
		Bank bank = new Bank();
		Account checkingAccount = new Account(Account.SAVINGS);
		bank.addCustomer(new Customer("Bill").openAccount(checkingAccount));

		checkingAccount.deposit(1500.0);

		assertEquals(2.0, bank.totalInterestPaid(), DOUBLE_DELTA);
	}

	@Test
	public void withdraw() {
		Bank bank = new Bank();
		Account checkingAccount = new Account(Account.CHECKING);
		Account savingAccount = new Account(Account.SAVINGS);
		Account maxiAccount = new Account(Account.MAXI_SAVINGS);

		Customer bill = new Customer("Bill").openAccount(checkingAccount);
		bill.openAccount(savingAccount);
		bill.openAccount(maxiAccount);
		bank.addCustomer(bill);

		checkingAccount.deposit(500);
		savingAccount.deposit(1000);

		bank.transferToAccount(bill, checkingAccount, savingAccount, 15);

		String str = "Statement for Bill\n"
				+ "\n"
				+ "Checking Account\n"
				+ "  deposit $500.00\n"
				+ "  withdrawal $15.00\n"
				+ "Total $485.00\n"
				+ "\n"
				+ "Savings Account\n"
				+ "  deposit $1,000.00\n"
				+ "  deposit $15.00\n"
				+ "Total $1,015.00\n"
				+ "\n"
				+ "Maxi Savings Account\n"
				+ "Total $0.00\n"
				+ "\n"
				+ "Total In All Accounts $1,500.00";

		assertEquals(str, bill.getStatement());
	}
}
