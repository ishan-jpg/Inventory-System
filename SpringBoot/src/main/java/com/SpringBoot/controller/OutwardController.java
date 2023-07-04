package com.SpringBoot.controller;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
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

import com.inventory.main.dto.OutwardDto;
import com.inventory.main.exception.ResourceNotFoundException;
import com.inventory.main.models.CustomerProduct;
import com.inventory.main.models.Godown;
import com.inventory.main.models.Outward;
import com.inventory.main.models.Product;
import com.inventory.main.service.CustomerProductService;
import com.inventory.main.service.GodownService;
import com.inventory.main.service.OutwardService;
import com.inventory.main.service.ProductService;

@RestController
@RequestMapping("/outwardregister")
public class OutwardController {

    @Autowired
    private ProductService productService;

    @Autowired
    private GodownService godownService;

    @Autowired
    private OutwardService outwardService;

    @Autowired
    private CustomerProductService customerProductService;

    @PostMapping("/add/{productId}/{godownId}")
    public ResponseEntity<?> postInwardRegister(@RequestBody Outward outward, @PathVariable("productId") int productId,
                                                @PathVariable("godownId") int godownId) {
        Product productFound = productService.getById(productId);

        if (productFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Product ID");
        }

        Godown godownFound = godownService.getById(godownId);

        if (godownFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid godown ID");
        }

        outward.setProduct(productFound);
        outward.setGodown(godownFound);

        outward.setDateOfDelivery(LocalDate.now());

        outward = outwardService.insert(outward);
        return ResponseEntity.status(HttpStatus.OK).body(outward);
    }

    @GetMapping("/all")
    public List<Outward> getAll() {
        return outwardService.getAll();
    }

    @GetMapping("/one/{id}")
    public ResponseEntity<?> getOne(@PathVariable int id) {
        Outward outwardFound = outwardService.getById(id);

        if (outwardFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid ID");
        }

        return ResponseEntity.status(HttpStatus.OK).body(outwardFound);
    }

    @PutMapping("/update/{id}/{productId}/{godownId}")
    public ResponseEntity<?> update(@PathVariable int id, @PathVariable("productId") int productId,
                                    @PathVariable("godownId") int godownId, @RequestBody Outward outward) {
        Outward outwardFound = outwardService.getById(id);

        if (outwardFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid ID");
        }

        outward.setId(id);

        Product productFound = productService.getById(productId);

        if (productFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Product ID");
        }

        Godown godownFound = godownService.getById(godownId);

        if (godownFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid godown ID");
        }

        outward.setProduct(productFound);
        outward.setGodown(godownFound);
        outward.setDateOfDelivery(outward.getDateOfDelivery());

        outward = outwardService.insert(outward);
        return ResponseEntity.status(HttpStatus.OK).body(outward);
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> delete(@PathVariable int id) {
        Outward outwardFound = outwardService.getById(id);

        if (outwardFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid ID");
        }

        outwardService.delete(outwardFound);
        return ResponseEntity.status(HttpStatus.OK).build();
    }

    @GetMapping("/report")
    public List<OutwardDto> outwardReport() {
        List<Outward> list = outwardService.getAll();
        List<OutwardDto> listDto = new ArrayList<>();
        list.stream().forEach(entry -> {
            OutwardDto dto = new OutwardDto();
            dto.setProductTitle(entry.getProduct().getTitle());
            dto.setProductQuantity(entry.getQuantity());
            dto.setGodownLocation(entry.getGodown().getLocation());
            dto.setGodownManager(entry.getGodown().getManager().getName());
            dto.setQuantity(entry.getQuantity());
            dto.setInvoiceNumber(entry.getInvoice());
            dto.setPurpose(entry.getPurpose());
            dto.setReceiptNo(entry.getRecieptNo());
            dto.setBillValue(entry.getBillValue());
            dto.setDeliveredTo(entry.getDeliveredTo());
            dto.setDateOfDelivery(entry.getDateOfDelivery());
            listDto.add(dto);
        });

        return listDto;
    }

    @GetMapping("/report/customer/{customerId}")
    public ResponseEntity<?> outwardReportByCustomer(@PathVariable int customerId) {
        List<CustomerProduct> list;
        try {
            list = customerProductService.getByCustomerId(customerId);
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid customer ID given");
        }

        HashMap<String, Integer> map = new HashMap<>();
        list.stream().forEach(entry -> {
            if (map.containsKey(entry.getProduct().getTitle())) {
                map.put(entry.getProduct().getTitle(),
                        map.get(entry.getProduct().getTitle()) + entry.getQuantityPurchased());
            } else {
                map.put(entry.getProduct().getTitle(), entry.getQuantityPurchased());
            }
        });

        return ResponseEntity.status(HttpStatus.OK).body(map);
    }

}