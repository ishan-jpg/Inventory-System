package com.SpringBoot.Service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.inventory.main.exception.ResourceNotFoundException;
import com.inventory.main.models.Inward;
import com.inventory.main.persistence.InwardRepository;

@Service
public class InwardService {

    @Autowired
    public InwardRepository inwardRepository;

    public Inward insert(Inward inward) {
        return inwardRepository.save(inward);
    }

    public List<Inward> getAll() {
        return inwardRepository.findAll();
    }

    public boolean checkQuantity(int productId, int quantityPuchased) {
        Inward inwardRegister = inwardRepository.checkQuantity(productId, quantityPuchased);

        if(inwardRegister == null) {
            return false;
        }

        return true;
    }

    public Inward getById(int id) {
        Optional<Inward> inwardFound = inwardRepository.findById(id);

        if(inwardFound.isEmpty()) {
            return null;
        }

        return inwardFound.get();
    }

    public void delete(Inward inward) {
        inwardRepository.delete(inward);
    }

    public List<Inward> getBySupplierId(int supplierId) throws ResourceNotFoundException {
        List<Inward> inwardRegisterList = inwardRepository.findAllBySupplierId(supplierId);

        if (inwardRegisterList == null) {
            throw new ResourceNotFoundException("Invalid ID given");
        }

        return inwardRegisterList;
    }


}
