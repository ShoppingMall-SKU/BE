package com.openMarket.backend.Ordering;


import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.bind.DefaultValue;

@Getter
@Setter
@AllArgsConstructor
public class OrderingInfoDTO {
    @NotBlank(message = "수령인은 필수 입력입니다.")
    private String receiverName;

    private String receiverPhone;

    @NotBlank(message = "배송지는 필수 입력입니다.")
    private String receiverAddress;

    private String message;

}
