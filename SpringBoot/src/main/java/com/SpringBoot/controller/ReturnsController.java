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
import com.inventory.main.models.Godown;
import com.inventory.main.models.Manager;
import com.inventory.main.models.Product;
import com.inventory.main.models.Returns;
import com.inventory.main.service.CustomerService;
import com.inventory.main.service.GodownService;
import com.inventory.main.service.ManagerService;
import com.inventory.main.service.ProductService;
import com.inventory.main.service.ReturnsService;

@RestController
@RequestMapping("/returns")
public class ReturnsController {

    @Autowired
    private ProductService productService;

    @Autowired
    private GodownService godownService;

    @Autowired
    private CustomerService customerService;

    @Autowired
    private ManagerService managerService;

    @Autowired
    private ReturnsService returnService;

    @PostMapping("/add/{productId}/{godownId}/{customerId}/{managerId}")
    public ResponseEntity<?> postInwardRegister(@RequestBody Returns returns,
                                                @PathVariable("productId") int productId, @PathVariable("godownId") int godownId,
                                                @PathVariable("customerId") int customerId, @PathVariable("managerId") int managerId) {
        Product productFound = productService.getById(productId);

        if (productFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Product ID");
        }

        Godown godownFound = godownService.getById(godownId);

        if (godownFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid godown ID");
        }

        Customer customerFound = customerService.getById(customerId);

        if (customerFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Customer Id");
        }

        Manager managerFound = managerService.getById(managerId);

        if (managerFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Manager ID");
        }

        returns.setProduct(productFound);
        returns.setGodown(godownFound);
        returns.setReturnedBy(customerFound);
        returns.setCheckedBy(managerFound);

        returns = returnService.insert(returns);
        return ResponseEntity.status(HttpStatus.OK).body(returns);
    }

    @GetMapping("/all")
    public List<Returns> getAll() {
        return returnService.getAll();
    }

    @GetMapping("/one/{id}")
    public ResponseEntity<?> getOne(@PathVariable int id) {
        Returns returns = returnService.getById(id);
        if(returns == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid ID");
        }

        return ResponseEntity.status(HttpStatus.OK).body(returns);
    }

    @PutMapping("/update/{id}/{productId}/{godownId}/{customerId}/{managerId}")
    public ResponseEntity<?> update(@PathVariable int id, @PathVariable("productId") int productId,
                                    @PathVariable("godownId") int godownId, @PathVariable("customerId") int customerId,
                                    @PathVariable("managerId") int managerId, @RequestBody Returns returns) {


        returns.setId(id);

        Product productFound = productService.getById(productId);

        if (productFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Product ID");
        }

        Godown godownFound = godownService.getById(godownId);

        if (godownFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid godown ID");
        }

        Customer customerFound = customerService.getById(customerId);

        if (customerFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Customer Id");
        }

        Manager managerFound = managerService.getById(managerId);

        if (managerFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Manager ID");
        }


        returns.setProduct(productFound);
        returns.setGodown(godownFound);
        returns.setReturnedBy(customerFound);
        returns.setCheckedBy(managerFound);

        returns = returnService.insert(returns);
        return ResponseEntity.status(HttpStatus.OK).body(returns);
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> delete(@PathVariable int id) {
        Returns returns = returnService.getById(id);
        if(returns == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid ID");
        }

        returnService.delete(returns);
        return ResponseEntity.status(HttpStatus.OK).body("Deleted......");
    }
}
