package com.SpringBoot.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.inventory.main.models.Manager;
import com.inventory.main.models.User;
import com.inventory.main.service.ManagerService;
import com.inventory.main.service.MyUserService;

@RestController
@RequestMapping("/manager")
public class ManagerController {

    @Autowired
    public ManagerService managerService;

    @Autowired
    public PasswordEncoder passwordEncoder;

    @Autowired
    public MyUserService userService;

    @PostMapping("/add")
    public Manager addManager(@RequestBody Manager manager) {

        User user = manager.getUser();

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        user = userService.insert(user);

        return managerService.insert(manager);
    }

    @GetMapping("/get")
    public List<Manager> getAllManager() {
        return managerService.getAll();
    }

    @GetMapping("/get/{managerId}")
    public ResponseEntity<?> getOneManager(@PathVariable("managerId") int managerId) {
        Manager managerFound = managerService.getById(managerId);

        if (managerFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Manager ID");
        }

        return ResponseEntity.status(HttpStatus.OK).body(managerFound);
    }

    @PutMapping("/update/{managerId}")
    public ResponseEntity<?> updateManager(@RequestBody Manager manager, @PathVariable("managerId") int managerId) {
        Manager managerFound = managerService.getById(managerId);

        if (managerFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Manager ID");
        }

        manager.setId(managerFound.getId());
        manager = managerService.insert(manager);
        return ResponseEntity.status(HttpStatus.OK).body(manager);
    }

    @DeleteMapping("/delete/{managerId}")
    public ResponseEntity<?> deleteManager(@PathVariable("managerId") int managerId){
        Manager managerFound = managerService.getById(managerId);

        if (managerFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Manager ID");
        }

        managerService.delete(managerFound);
        return ResponseEntity.status(HttpStatus.OK).body("Deleted.....");
    }
}
