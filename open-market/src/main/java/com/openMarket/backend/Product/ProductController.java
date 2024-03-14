package com.openMarket.backend.Product;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/product")
public class ProductController {

    private final ProductService productService;

    @GetMapping("/list") // 전체 조회 test완
    public ResponseEntity<List<Product>> getProductList(){
        List<Product> productList = this.productService.getAll();
        return ResponseEntity.ok(productList);
    }

    @GetMapping("/list/{name}") // 검색기능 test완
    public ResponseEntity<List<Product>> getProductByName(@PathVariable String name) {
        List<Product> product = productService.searchByName(name);
        // 데이터가 없는 경우 빈 리스트 반환
        if (product.isEmpty()) {
            return ResponseEntity.ok(Collections.emptyList());
        }
        return ResponseEntity.ok(product);
    }

    @GetMapping("/list/brands/{brand}") // brand별 검색 기능 test완
    public ResponseEntity<List<Product>> getProductByBrand(@PathVariable String brand){
        List<Product> products = productService.getByBrand(brand);
        return ResponseEntity.ok(products);
    }

    @GetMapping("/detail/{id}") // 상품 상세 조회 test완
    public ResponseEntity<Product> getProductDetail(@PathVariable int id){
        Product product = this.productService.getProductById(id);
        return ResponseEntity.ok(product);
    }

    @PostMapping("/create-product") // test완
    public ResponseEntity<List<Product>> postProduct(@RequestBody ProductPostDto productPostDto){
        productService.createProduct(productPostDto.getName(), productPostDto.getDetail(),productPostDto.getPrice(),
                productPostDto.getImg(),productPostDto.getSale(),productPostDto.getStock(),
                productPostDto.getBrand(),productPostDto.getStatus());
        return ResponseEntity.ok(productService.getAll());
    }

    @PatchMapping("/detail/{id}")
    public ResponseEntity<List<Product>> pathProduct(@PathVariable int id, @RequestBody ProductPathDto productPathDto){
        Product product = productService.getProductById(id);
        productService.modifiedProduct(product, productPathDto.getName(),productPathDto.getImg(),
                productPathDto.getPrice(), productPathDto.getStock());

        return ResponseEntity.ok((productService.getAll()));
    }

    @PatchMapping("/detail/sale/{id}")
    public ResponseEntity<List<Product>> pathProductSale(@PathVariable int id, @RequestBody ProductPathDto productPathDto){
        Product product = productService.getProductById(id);
        productService.modifiedSale(product, productPathDto.getSale());

        return ResponseEntity.ok((productService.getAll()));
    }

    @DeleteMapping("/detail/{id}")
    public ResponseEntity<List<Product>> deleteProduct(@PathVariable int id){
        Product product = productService.getProductById(id);
        productService.deleteProduct(product);

        return ResponseEntity.ok(productService.getAll());
    }
}
