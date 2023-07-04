package com.SpringBoot.Service;


import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.inventory.main.models.Product;
import com.inventory.main.persistence.ProductRepository;

@Service
public class ProductService {

    @Autowired
    public ProductRepository productRepository;

    public Product insert(Product product) {
        return productRepository.save(product);
    }

    public Product getById(int productId) {
        Optional<Product> productFound = productRepository.findById(productId);
        if(!productFound.isPresent()) {
            return null;
        }

        return productFound.get();
    }

    public List<Product> getAll() {
        return productRepository.findAll();
    }

    public void delete(Product productFound) {
        productRepository.delete(productFound);
    }


}
