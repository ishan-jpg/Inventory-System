package com.SpringBoot.Service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.inventory.main.models.Manager;
import com.inventory.main.persistence.ManagerRepository;

@Service
public class ManagerService {

    @Autowired
    public ManagerRepository managerRepository;

    public Manager insert(Manager manager) {
        return managerRepository.save(manager);
    }

    public Manager getById(int managerId) {
        Optional<Manager> managerFound = managerRepository.findById(managerId);
        if(!managerFound.isPresent()) {
            return null;
        }

        return managerFound.get();
    }

    public List<Manager> getAll() {
        return managerRepository.findAll();
    }

    public void delete(Manager managerFound) {
        managerRepository.delete(managerFound);
    }

}
