package com.SpringBoot.Service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;

import com.inventory.main.models.Customer;
import com.inventory.main.persistence.CustomerRepository;

public class CustomerService {

    @Autowired
    public CustomerRepository customerRepository;

    public Customer insert(Customer customer) {
        return customerRepository.save(customer);
    }

    public List<Customer> getAll() {
        return customerRepository.findAll();
    }

    public Customer getById(int customerId) {
        Optional<Customer> customerFound = customerRepository.findById(customerId);
        if(!customerFound.isPresent()) {
            return null;
        }

        return customerFound.get();
    }

    public void delete(Customer customerFound) {
        customerRepository.delete(customerFound);
    }

}
