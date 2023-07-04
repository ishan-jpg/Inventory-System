package com.SpringBoot.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.inventory.main.models.Product;
import com.inventory.main.service.ProductService;

@RestController
@RequestMapping("/product")
public class ProductController {

    @Autowired
    public ProductService productService;

    @PostMapping("/add")
    public Product addProduct(@RequestBody Product product) {
        return productService.insert(product);
    }

    @GetMapping("/get")
    public List<Product> getAllProduct(){
        return productService.getAll();
    }

    @GetMapping("/get/{productId}")
    public ResponseEntity<?> getOneProduct(@PathVariable("productId") int productId) {
        Product productFound = productService.getById(productId);

        if (productFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Product ID");
        }

        return ResponseEntity.status(HttpStatus.OK).body(productFound);
    }

    @PutMapping("/update/{productId}")
    public ResponseEntity<?> updateProduct(@RequestBody Product product, @PathVariable("productId") int productId){
        Product productFound = productService.getById(productId);

        if (productFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Product ID");
        }

        product.setId(productFound.getId());
        product = productService.insert(product);

        return ResponseEntity.status(HttpStatus.OK).body(product);
    }

    @DeleteMapping("/delete/{productId}")
    public ResponseEntity<?> deleteProduct(@PathVariable("productId") int productId){
        Product productFound = productService.getById(productId);

        if (productFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Product ID");
        }

        productService.delete(productFound);

        return ResponseEntity.status(HttpStatus.OK).body("Deleted.....");
    }
}

