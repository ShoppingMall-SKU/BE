package com.openMarket.backend.OrderDetail;


import com.openMarket.backend.Ordering.Ordering;
import com.openMarket.backend.Product.Product;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class OrderDetailService {
    private final OrderDetailRepository orderDetailRepository;

    public void create(Ordering ordering, Product product,  int quantity, int price) {
        OrderDetail orderDetail = new OrderDetail();
        orderDetail.setOrdering(ordering);
        orderDetail.setProduct(product);
        orderDetail.setQuantity(quantity);
        orderDetail.setShipStatus("결제 확인 중");
        orderDetail.setPrice(price);

        this.orderDetailRepository.save(orderDetail);

    }

    public List<OrderDetail> getOrderDetailAll() {
        return this.orderDetailRepository.findAll();
    }

    public OrderDetail getOrderDetailById(int id) {
        return this.orderDetailRepository.findById(id).orElse(null);
    }

    public List<OrderDetail> getOrderDetailByOrdering(Ordering ordering) {
        return this.orderDetailRepository.findByOrdering(ordering);
    }

    public void updateShipStatus(OrderDetail orderDetail, String status) {
        orderDetail.setShipStatus(status);
        this.orderDetailRepository.save(orderDetail);
    }


    public void delete(OrderDetail orderDetail) {
        this.orderDetailRepository.delete(orderDetail);
    }

}
