package com.openMarket.backend.Payment;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface PaymentRepository extends JpaRepository<Payment, Integer> {

    // UserId를 이용해 Payment list 반환 쿼리문 작성 필요
    @Query("")
    List<Payment> findPaymentByUserId(int userId);

    Payment findPaymentById(int id);
    Payment findPaymentByOrderingId(int orderingId);
}
