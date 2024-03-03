package com.openMarket.backend.Cart;

import com.openMarket.backend.User.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface CartRepository extends JpaRepository<Cart, Integer>{
    List<Cart> findByUserId(int id);
    Cart findById(int cartId);

}
