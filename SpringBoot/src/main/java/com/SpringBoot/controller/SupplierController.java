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

import com.inventory.main.models.Supplier;
import com.inventory.main.service.SupplierService;

@RestController
@RequestMapping("/supplier")
public class SupplierController {

    @Autowired
    public SupplierService supplierService;

    @PostMapping("/add")
    public Supplier addSupplier(@RequestBody Supplier supplier) {
        return supplierService.insert(supplier);
    }

    @GetMapping("/get")
    public List<Supplier> getAllSupplier() {
        return supplierService.getAll();
    }

    @GetMapping("/get/{supplierId}")
    public ResponseEntity<?> getOneSupplier(@PathVariable("SupplierId") int supplierId) {
        Supplier supplierFound = supplierService.getById(supplierId);

        if (supplierFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Supplier ID");
        }

        return ResponseEntity.status(HttpStatus.OK).body(supplierFound);
    }

    @PutMapping("/update/{supplierId}")
    public ResponseEntity<?> updateSupplier(@PathVariable("SupplierId") int supplierId,
                                            @RequestBody Supplier supplier) {
        Supplier supplierFound = supplierService.getById(supplierId);

        if (supplierFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Supplier ID");
        }

        supplier.setId(supplierFound.getId());
        supplier = supplierService.insert(supplier);
        return ResponseEntity.status(HttpStatus.OK).body(supplier);
    }

    @DeleteMapping("/delete/{supplierId}")
    public ResponseEntity<?> deleteSupplier(@PathVariable("SupplierId") int supplierId){

        Supplier supplierFound = supplierService.getById(supplierId);

        if (supplierFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Supplier ID");
        }

        supplierService.delete(supplierFound);
        return ResponseEntity.status(HttpStatus.OK).body("Deleted.....");
    }
}
