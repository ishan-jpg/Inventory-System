package com.SpringBoot.Service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.inventory.main.models.Supplier;
import com.inventory.main.persistence.SupplierRepository;

@Service
public class SupplierService {

    @Autowired
    public SupplierRepository supplierRepository;

    public Supplier insert(Supplier supplier) {
        return supplierRepository.save(supplier);
    }

    public Supplier getById(int supplierId) {
        Optional<Supplier> supplierFound = supplierRepository.findById(supplierId);
        if(!supplierFound.isPresent()) {
            return null;
        }

        return supplierFound.get();
    }

    public List<Supplier> getAll() {
        return supplierRepository.findAll();
    }

    public void delete(Supplier supplierFound) {
        supplierRepository.delete(supplierFound);
    }


}

