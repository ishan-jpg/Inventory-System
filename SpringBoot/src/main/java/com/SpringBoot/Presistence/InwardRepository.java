package com.SpringBoot.Presistence.;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.inventory.main.models.Inward;

public interface InwardRepository extends JpaRepository<Inward, Integer>{

    @Query("select ir from InwardRegister ir where ir.product.id=?1 AND ir.quantity >= ?2")
    Inward checkQuantity(int productId, int quantityPurchased);

    @Query("select ir from InwardRegister ir where ir.supplier.id=?1")
    List<Inward> findAllBySupplierId(int supplierId);
}
