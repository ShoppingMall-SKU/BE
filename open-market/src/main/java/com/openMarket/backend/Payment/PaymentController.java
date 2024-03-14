package com.openMarket.backend.Payment;

import com.siot.IamportRestClient.IamportClient;
import com.siot.IamportRestClient.response.IamportResponse;
import com.siot.IamportRestClient.response.Payment;
import java.io.IOException;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@Slf4j // log 찍는 어노테이션
@RequiredArgsConstructor
@RequestMapping("/api/payment")
public class PaymentController {

    private final PaymentService paymentService;
    private final RefundService refundService;
    private IamportClient iamportClient;

//    @Value("${imp.api.key}")
//    private String apiKey;
//
//    @Value("${imp.api.secretkey}")
//    private String secretKey;

//    @PostConstruct
//    public void init() {
//        this.iamportClient = new IamportClient(apiKey, secretKey);
//    }
//
//
//    //CRUD
//    @PostMapping("/payments")
//    public ResponseEntity<String> createPayment(@RequestBody PaymentDTO paymentDTO)throws IOException{
//        String orderingId = Integer.toString(paymentDTO.getOrdering().getId());
//        try {
//            int userId = paymentDTO.getOrdering().getUser().getId(); // 수정 필요
//
//            paymentService.createPayment(paymentDTO.getMethod(), paymentDTO.getAmount(), paymentDTO.getOrdering());
//            log.info("결제 성공 : 주문 번호 {}", orderingId);
//            return ResponseEntity.ok().build();
//        } catch (RuntimeException e){
//            log.info("주문 상품 환불 진행 : 주문 번호 {}", orderingId);
//            String token = refundService.getToken(apiKey, secretKey);
//            refundService.refundRequest(token, orderingId, e.getMessage());
//            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
//        }
//
//    }
    // imp_uid(결제 고유 ID) 값을 받아 결제 상세 내역을 조회하는 함수
    @PostMapping("/payment/{imp_uid}")
    public IamportResponse<Payment> validateIamport(@PathVariable String imp_uid){
        IamportResponse<Payment> payment = iamportClient.paymentByImpUid(imp_uid);
        log.info("결제 요청 응답. 결제 내역 - 주문 번호 : {}",payment.getResponse().getMerchantUid());
        return payment;
    }


    // Read userId Payment List
//    @GetMapping("/list/{userId}")
//    public ResponseEntity<List<Payments>> getPaymentListByUserId(@PathVariable int userId){
//        List<Payments> paymentList = paymentService.getPaymentListByUserId(userId);
//        return ResponseEntity.ok(paymentList);
//    }

}
