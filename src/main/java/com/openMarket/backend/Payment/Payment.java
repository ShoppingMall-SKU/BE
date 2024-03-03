package com.openMarket.backend.Payment;


import com.openMarket.backend.Ordering.Ordering;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@Table(name = "payment")
public class Payment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String method;

    private int amount;

    private LocalDateTime paymentDate;

    @OneToOne
    @JoinColumn(name = "ordering_id")
    private Ordering ordering;
}
