package com.SpringBoot.Presistence;

import org.springframework.data.jpa.repository.JpaRepository;

import com.inventory.main.models.Product;

public interface ProductRepository extends JpaRepository<Product, Integer>{

}
