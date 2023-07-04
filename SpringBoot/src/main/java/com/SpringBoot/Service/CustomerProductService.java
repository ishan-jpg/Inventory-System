package com.SpringBoot.Service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;

import com.inventory.main.exception.ResourceNotFoundException;
import com.inventory.main.models.CustomerProduct;
import com.inventory.main.persistence.CustomerProductRepository;

public class CustomerProductService {

    @Autowired
    public CustomerProductRepository customerProductRepository;

    public CustomerProduct insert(CustomerProduct customerProduct) {
        return customerProductRepository.save(customerProduct);
    }

    public List<CustomerProduct> getAll() {
        return customerProductRepository.findAll();
    }

    public CustomerProduct getById(int id) {
        Optional<CustomerProduct> customerProductFound = customerProductRepository.findById(id);
        if(!customerProductFound.isPresent()) {
            return null;
        }

        return customerProductFound.get();
    }

    public List<CustomerProduct> getByCustomerId(int customerId) throws ResourceNotFoundException {
        List<CustomerProduct> customerProductList = customerProductRepository.findAllByCustomerId(customerId);

        if (customerProductList == null) {
            throw new ResourceNotFoundException("Invalid ID given");
        }

        return customerProductList;
    }

    public void delete(CustomerProduct customerProductFound) {
        customerProductRepository.delete(customerProductFound);
    }

}
