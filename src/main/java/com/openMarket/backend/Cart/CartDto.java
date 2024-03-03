package com.openMarket.backend.Cart;

import com.openMarket.backend.Product.Product;
import com.openMarket.backend.User.User;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Data
@NoArgsConstructor
public class CartDto {
    private int quantity;
    private User user;
    private Product product;
}
