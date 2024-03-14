package com.openMarket.backend.Payment;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface PaymentRepository extends JpaRepository<Payments, Integer> {

    // UserId를 이용해 Payment list 반환 쿼리문 작성 필요
    @Query("select p from Payments as p, User as u where u.id = p.ordering.user.id")
    List<Payments> findPaymentByUserId(int userId);

    Payments findPaymentById(int id);
    Payments findPaymentByOrderingId(int orderingId);
}
