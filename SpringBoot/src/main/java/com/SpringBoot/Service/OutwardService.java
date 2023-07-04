package com.SpringBoot.Service;



import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;

import com.inventory.main.models.Outward;
import com.inventory.main.persistence.OutwardRepository;

public class OutwardService {

    @Autowired
    public OutwardRepository outwardRepository;

    public List<Outward> getAll() {
        return outwardRepository.findAll();
    }

    public Outward insert(Outward outward) {
        return outwardRepository.save(outward);
    }

    public Outward getById(int id) {
        Optional<Outward> outwardFound = outwardRepository.findById(id);

        if(outwardFound.isEmpty()) {
            return null;
        }

        return outwardFound.get();
    }

    public void delete(Outward outward) {
        outwardRepository.delete(outward);
    }

}


