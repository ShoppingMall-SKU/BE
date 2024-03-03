package com.openMarket.backend.OrderDetail;

import com.openMarket.backend.Ordering.Ordering;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface OrderDetailRepository extends JpaRepository<OrderDetail, Integer> {
    List<OrderDetail> findByOrdering(Ordering ordering);
}
