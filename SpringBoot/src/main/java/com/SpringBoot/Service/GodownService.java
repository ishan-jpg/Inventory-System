package com.SpringBoot.Service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.inventory.main.models.Godown;
import com.inventory.main.persistence.GodownRepository;

@Service
public class GodownService {

    @Autowired
    public GodownRepository godownRepository;

    public Godown insert(Godown godown) {
        return godownRepository.save(godown);
    }

    public Godown getById(int godownId) {
        Optional<Godown> godownFound = godownRepository.findById(godownId);
        if(!godownFound.isPresent()) {
            return null;
        }

        return godownFound.get();
    }

    public List<Godown> getAll() {
        return godownRepository.findAll();
    }

    public void delete(Godown godownFound) {
        godownRepository.delete(godownFound);
    }

}

