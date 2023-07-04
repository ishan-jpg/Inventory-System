package com.SpringBoot.Service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.inventory.main.models.Returns;
import com.inventory.main.persistence.ReturnsRepository;

@Service
public class ReturnsService {

    @Autowired
    public ReturnsRepository returnsRepository;

    public List<Returns> getAll() {
        return returnsRepository.findAll();
    }

    public Returns getById(int id) {
        Optional<Returns> returnFound = returnsRepository.findById(id);
        if(returnFound.isEmpty()) {
            return null;
        }

        return returnFound.get();
    }

    public void delete(Returns returns) {
        returnsRepository.delete(returns);
    }

    public Returns insert(Returns returns) {
        return returnsRepository.save(returns);
    }


}
