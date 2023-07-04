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

import com.inventory.main.models.Godown;
import com.inventory.main.models.Manager;
import com.inventory.main.service.GodownService;
import com.inventory.main.service.ManagerService;

@RestController
@RequestMapping("/godown")
public class GodownController {

    @Autowired
    public GodownService godownService;

    @Autowired
    public ManagerService managerService;

    @PostMapping("/add/{managerId}")
    public ResponseEntity<?> addGodown(@RequestBody Godown godown, @PathVariable("managerId") int managerId) {
        Manager managerFound = managerService.getById(managerId);
        if (managerFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Manager ID");
        }

        godown.setManager(managerFound);
        godown = godownService.insert(godown);
        return ResponseEntity.status(HttpStatus.OK).body(godown);
    }

    @GetMapping("/get")
    public List<Godown> getAllGodown() {
        return godownService.getAll();
    }

    @GetMapping("/get/{godownId}")
    public ResponseEntity<?> getOneGodown(@PathVariable int godownId) {
        return godownService.getById(godownId)==null?
                ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Godown ID"):
                ResponseEntity.status(HttpStatus.OK).body(godownService.getById(godownId));
    }

    @PutMapping("/update/{godownId}")
    public ResponseEntity<?> updateGodown(@RequestBody Godown godown, @PathVariable("godownId") int godownId) {
        Godown godownFound = godownService.getById(godownId);

        if (godownFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid godown ID");
        }
        godown.setId(godownFound.getId());
        godown = godownService.insert(godown);
        return ResponseEntity.status(HttpStatus.OK).body(godown);
    }

    @DeleteMapping("/delete/{godownId}")
    public ResponseEntity<?> deleteGodown(@PathVariable("godownId") int godownId) {
        Godown godownFound = godownService.getById(godownId);

        if (godownFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid godown ID");
        }

        godownService.delete(godownFound);

        return ResponseEntity.status(HttpStatus.OK).body("Deleted....");
    }

}
