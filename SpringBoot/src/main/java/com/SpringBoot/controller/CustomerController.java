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

import com.inventory.main.models.Customer;
import com.inventory.main.service.CustomerService;

@RestController
@RequestMapping("/customer")
public class CustomerController {

    @Autowired
    public CustomerService customerService;

    @PostMapping("/add")
    public Customer addCustomer(@RequestBody Customer customer) {
        return customerService.insert(customer);
    }

    @GetMapping("/get")
    public List<Customer> getAllCustomer() {
        return customerService.getAll();
    }

    @GetMapping("/get/{customerId}")
    public ResponseEntity<?> getOneCustomer(@PathVariable("customerId") int customerId) {
        Customer customerFound = customerService.getById(customerId);

        if (customerFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Customer Id");
        }

        return ResponseEntity.status(HttpStatus.OK).body(customerFound);
    }

    @PutMapping("/update/{customerId}")
    public ResponseEntity<?> updateCustomer(@PathVariable("customerId") int customerId,
                                            @RequestBody Customer customer) {
        Customer customerFound = customerService.getById(customerId);

        if (customerFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Customer Id");
        }

        customer.setId(customerId);
        customer = customerService.insert(customer);
        return ResponseEntity.status(HttpStatus.OK).body(customer);
    }

    @DeleteMapping("/delete/{customerId}")
    public ResponseEntity<?> deleteCustomer(@PathVariable("customerId") int customerId){
        Customer customerFound = customerService.getById(customerId);

        if (customerFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Customer Id");
        }

        customerService.delete(customerFound);
        return ResponseEntity.status(HttpStatus.OK).body("Deleted...");
    }
}
