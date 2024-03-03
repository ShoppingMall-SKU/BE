package com.openMarket.backend.Product;

import com.openMarket.backend.Product.Product.*;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;


@Getter
@Setter
@Data
@NoArgsConstructor
public class ProductPathDto {
    private String name;

    private String detail;

    private int price;

    private String img;

    private int sale;

    private int stock;


    private LocalDateTime create_date;

    private String brand;

    private status status;

}
