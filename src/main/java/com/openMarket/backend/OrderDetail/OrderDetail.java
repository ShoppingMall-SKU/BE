package com.openMarket.backend.OrderDetail;


import com.openMarket.backend.Ordering.Ordering;
import com.openMarket.backend.Product.Product;
import com.openMarket.backend.User.User;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
public class OrderDetail {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String shipStatus;

    @JoinColumn(name = "order_id")
    @ManyToOne
    private Ordering ordering;

    @JoinColumn(name = "product_id")
    @ManyToOne
    private Product product;

    private int quantity;

    private int price;

}
