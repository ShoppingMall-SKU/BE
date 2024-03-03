package com.openMarket.backend.Ordering;


import com.openMarket.backend.Product.Product;
import com.openMarket.backend.User.User;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
public class Ordering {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String receiverName;

    private String receiverPhone;

    private String receiverAddress;

    private String message;

    private LocalDateTime orderDate;

    private int totalPrice;

    @JoinColumn(name = "user_id")
    @ManyToOne
    private User user;

}
