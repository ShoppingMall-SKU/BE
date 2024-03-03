package com.openMarket.backend.Product;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/product")
public class ProductController {

    private final ProductService productService;

    @GetMapping("/list")
    public ResponseEntity<List<Product>> getProductList(){
        List<Product> productList = this.productService.getAll();
        return ResponseEntity.ok(productList);
    }

    @GetMapping("/detail/{id}")
    public ResponseEntity<Product> getProductDetail(@PathVariable int id){
        Product product = this.productService.getProductById(id);
        return ResponseEntity.ok(product);
    }

    @PostMapping("/create-product")
    public ResponseEntity<List<Product>> postProduct(@RequestBody ProductPostDto productPostDto){
        productService.createProduct(productPostDto.getName(), productPostDto.getDetail(),productPostDto.getPrice(),
                productPostDto.getImg(),productPostDto.getSale(),productPostDto.getStock(),
                productPostDto.getBrand(),productPostDto.getStatus());
        return ResponseEntity.ok(productService.getAll());
    }
    @PatchMapping("/detail/{id}")
    public ResponseEntity<List<Product>> pathProduct(@PathVariable int id, @RequestBody ProductPathDto productPathDto){
        Product product = productService.getProductById(id);
        productService.modifiedProduct(product, productPathDto.getName(),productPathDto.getImg(),productPathDto.getPrice());

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
