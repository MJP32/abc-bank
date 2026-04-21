package com.abc.domain;

import jakarta.persistence.*;

import java.util.Date;

@Entity
@Table(name = "bank_transaction")
public class Transaction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    public double amount;

    @Temporal(TemporalType.TIMESTAMP)
    private Date transactionDate;

    protected Transaction() {}

    public Transaction(double amount) {
        this.amount = amount;
        this.transactionDate = DateProvider.getInstance().now();
    }

}
