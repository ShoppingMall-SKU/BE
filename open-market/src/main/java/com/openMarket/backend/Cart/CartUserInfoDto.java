package com.openMarket.backend.Cart;

import com.openMarket.backend.Product.Product;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Data
@NoArgsConstructor
public class CartUserInfoDto {
    private String userEmail;
    private Product product;
    private int quantity;
}
