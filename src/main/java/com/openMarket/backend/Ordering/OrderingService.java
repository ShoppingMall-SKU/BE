package com.openMarket.backend.Ordering;


import com.openMarket.backend.Cart.Cart;
import com.openMarket.backend.Cart.CartRepository;
import com.openMarket.backend.OrderDetail.OrderDetail;
import com.openMarket.backend.OrderDetail.OrderDetailRepository;
import com.openMarket.backend.OrderDetail.OrderDetailService;
import com.openMarket.backend.User.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class OrderingService {
    private final OrderingRepository orderingRepository;
    private final CartRepository cartRepository;
    private final OrderDetailService orderDetailService;

    public void create(User user, String name, String phone, String address, String msg) {
        Ordering ordering = new Ordering();
        ordering.setUser(user);
        ordering.setReceiverName(name);
        ordering.setReceiverPhone(phone);
        ordering.setReceiverAddress(address);
        ordering.setMessage(msg);
        ordering.setOrderDate(LocalDateTime.now());
        orderingRepository.save(ordering);

        List<Cart> cartList = cartRepository.findByUserId(user.getId());
        int price = 0;
        for (Cart c : cartList) {
            price += (c.getProduct().getPrice() * c.getQuantity());
            orderDetailService.create(
                    ordering,
                    c.getProduct(),
                    c.getQuantity(),
                    c.getProduct().getPrice() * c.getQuantity()
            );

        }

        ordering.setTotalPrice(price);

        this.orderingRepository.save(ordering);


    }

    public List<Ordering> getOrderingByUser(User user) {
        return this.orderingRepository.findByUser(user);
    }


    public void delete(Ordering ordering) {
        this.orderingRepository.delete(ordering);
    }
}
