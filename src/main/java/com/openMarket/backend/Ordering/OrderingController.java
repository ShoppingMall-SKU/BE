package com.openMarket.backend.Ordering;


import com.openMarket.backend.OrderDetail.OrderDetailService;
import com.openMarket.backend.User.User;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/ordering")
@RequiredArgsConstructor
public class OrderingController {
    private final OrderingService orderingService;
    private final OrderDetailService orderDetailService;

    @PostMapping("/create") // 결제 전 정보 기입. 토큰에서 유저 정보 가져옴. 나중에 작업하자
    public void create(HttpServletRequest request, @RequestParam OrderingInfoDTO infoDTO) {

    }

//    @GetMapping("/list/{id}")
//    public ResponseEntity<>


}
