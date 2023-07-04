package com.SpringBoot.controller;

import java.time.LocalDate;
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

import com.inventory.main.models.Customer;
import com.inventory.main.models.CustomerProduct;
import com.inventory.main.models.Product;
import com.inventory.main.service.CustomerProductService;
import com.inventory.main.service.CustomerService;
import com.inventory.main.service.InwardService;
import com.inventory.main.service.ProductService;

@RestController
@RequestMapping("/customer-product")
public class CustomerProductController {

    @Autowired
    private CustomerService customerService;

    @Autowired
    private ProductService productService;

    @Autowired
    private CustomerProductService customerProductService;

    @Autowired
    private InwardService inwardRegisterService;

    @PostMapping("/purchase/{customerId}/{productId}")
    public ResponseEntity<?> purchaseApi(@RequestBody CustomerProduct customerProduct,
                                         @PathVariable("customerId") int customerId, @PathVariable("productId") int productId) {
        Customer customerFound = customerService.getById(customerId);

        if (customerFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Customer Id");
        }

        Product productFound = productService.getById(productId);

        if (productFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Product ID");
        }

        customerProduct.setCustomer(customerFound);
        customerProduct.setProduct(productFound);
        customerProduct.setDateOfPurchase(LocalDate.now());

        boolean status = inwardRegisterService.checkQuantity(productId, customerProduct.getQuantityPurchased());
        if (status == false)
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body("Product out of stock");

        customerProduct = customerProductService.insert(customerProduct);
        return ResponseEntity.status(HttpStatus.OK).body(customerProduct);
    }

    @GetMapping("/all")
    public List<CustomerProduct> getAll() {
        return customerProductService.getAll();
    }

    @GetMapping("/one/{id}")
    public ResponseEntity<?> getOne(@PathVariable int id) {
        CustomerProduct customerProductFound = customerProductService.getById(id);

        if (customerProductFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid ID");
        }

        return ResponseEntity.status(HttpStatus.OK).body(customerProductFound);
    }

    @PutMapping("/update/{id}/{customerId}/{productId}")
    public ResponseEntity<?> update(@PathVariable int id, @PathVariable("customerId") int customerId,
                                    @PathVariable("productId") int productId, @RequestBody CustomerProduct customerProduct) {
        CustomerProduct customerProductFound = customerProductService.getById(id);

        if (customerProductFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid ID");
        }

        customerProduct.setId(id);

        Customer customerFound = customerService.getById(customerId);

        if (customerFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Customer Id");
        }

        Product productFound = productService.getById(productId);

        if (productFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Product ID");
        }

        customerProduct.setCustomer(customerFound);
        customerProduct.setProduct(productFound);
        customerProduct.setDateOfPurchase(customerProduct.getDateOfPurchase());

        boolean status = inwardRegisterService.checkQuantity(productId, customerProduct.getQuantityPurchased());
        if (status == false)
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body("Product out of stock");

        customerProduct = customerProductService.insert(customerProduct);
        return ResponseEntity.status(HttpStatus.OK).body(customerProduct);
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> delete(@PathVariable int id) {
        CustomerProduct customerProductFound = customerProductService.getById(id);

        if (customerProductFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid ID");
        }

        customerProductService.delete(customerProductFound);
        return ResponseEntity.status(HttpStatus.OK).build();
    }

}