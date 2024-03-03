package com.openMarket.backend.Product;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.LocalDateTime;

@Entity
@Getter
@Setter
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String name;

    private String detail;

    private int price;

    private String img;

    private int sale;

    private int stock;

    private LocalDateTime create_date;

    private String brand;

    @PreUpdate
    public void preUpdate() {this.create_date = LocalDateTime.now();}

    private status status;

    public enum status {
        STATUS_COLD("냉장"),
        STATUS_FROZEN("냉동"),
        STATUS_ROOM_TEMP("실온");

        private String status;

        status(String status) {
            this.status = status;
        }

        public String getStatus() {
            return status;
        }

    }

}
