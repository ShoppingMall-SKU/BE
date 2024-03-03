package com.openMarket.backend.Product;

import com.openMarket.backend.User.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class ProductService {
    private final ProductRepository productRepository;

    //CRUD
    // Create Product
    public void createProduct(String name, String detail, int price, String img, int sale, int stock,
                              String brand, Product.status staus){
        Product product = new Product();
        product.setName(name);
        product.setDetail(detail);
        product.setPrice(price);
        product.setImg(img);
        product.setSale(sale);
        product.setStock(stock);
        product.setBrand(brand);
        product.setStatus(staus);
        product.setCreate_date(LocalDateTime.now());

        this.productRepository.save(product);
    }

    // Read Product
    public Product getProductById(int id){
        Optional<Product> product = this.productRepository.findById(id);
        if(product.isPresent()){
            return product.get();
        }else{
            throw new RuntimeException("Data Not Found");
        }
    }
    public Product getProductByName(String name){
        Optional<Product> product = this.productRepository.findByName(name);
        if(product.isPresent()){
            return product.get();
        }else{
            throw new RuntimeException("Data Not Found");
        }
    }
    public List<Product> getAll(){
        return productRepository.findAll();
    }
    public List<Product> searchByName(String name){ // 검색기능
        List<Product> products = this.productRepository.findAll();
        products.removeIf(s->!s.getName().contains(name));
        return products;
    }

    // Update Product
    // User 추가하여 인증 수정해야함
    public void modifiedProduct(Product product, String name, String img, int price){
        product.setName(name);
        product.setImg(img);
        product.setPrice(price);

        this.productRepository.save(product);
    }
    public void modifiedSale(Product product, int sale){
        product.setSale(sale);
        this.productRepository.save(product);
    }
    // Delete Product
    public void deleteProduct(Product product){
        this.productRepository.delete(product);
    }
}
