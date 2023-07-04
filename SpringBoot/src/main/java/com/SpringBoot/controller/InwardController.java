package com.inventory.main.controller;

import java.time.LocalDate;
import java.util.ArrayList;
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

import com.inventory.main.dto.InwardBySupplierDto;
import com.inventory.main.dto.InwardDto;
import com.inventory.main.exception.ResourceNotFoundException;
import com.inventory.main.models.Godown;
import com.inventory.main.models.Inward;
import com.inventory.main.models.Product;
import com.inventory.main.models.Supplier;
import com.inventory.main.service.GodownService;
import com.inventory.main.service.InwardService;
import com.inventory.main.service.ProductService;
import com.inventory.main.service.SupplierService;

@RestController
@RequestMapping("/inward")
public class InwardController {

    @Autowired
    public GodownService godownService;

    @Autowired
    public ProductService productService;

    @Autowired
    public SupplierService supplierService;

    @Autowired
    public InwardService inwardService;

    @PostMapping("/add/{productId}/{godownId}/{supplierId}")
    public ResponseEntity<?> addInward(@RequestBody Inward inward, @PathVariable("productId") int productId,
                                       @PathVariable("godownId") int godownId, @PathVariable("supplierId") int supplierId) {
        Godown godownFound = godownService.getById(godownId);
        if (godownFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Godown ID");
        }

        Product productFound = productService.getById(productId);
        if (productFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Product ID");
        }

        Supplier supplierFound = supplierService.getById(supplierId);
        if (supplierFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Supplier ID");
        }

        inward.setGodown(godownFound);
        inward.setSupplier(supplierFound);
        inward.setProduct(productFound);
        inward.setDateOfSupply(LocalDate.now());

        inward = inwardService.insert(inward);

        return ResponseEntity.status(HttpStatus.OK).body(inward);
    }

    @GetMapping("/get")
    public List<Inward> getAllInward() {
        return inwardService.getAll();
    }

    @GetMapping("/one/{id}")
    public ResponseEntity<?> getOne(@PathVariable int id) {
        Inward inwardFound = inwardService.getById(id);

        if (inwardFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Id");
        }

        return ResponseEntity.status(HttpStatus.OK).body(inwardFound);
    }

    @PutMapping("/update/{id}/{productId}/{godownId}/{supplierId}")
    public ResponseEntity<?> update(@PathVariable("id") int id, @PathVariable("productId") int productId,
                                    @PathVariable("godownId") int godownId, @PathVariable("supplierId") int supplierId,
                                    @RequestBody Inward inward) {
        Inward inwardFound = inwardService.getById(id);

        if (inwardFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Id");
        }

        inward.setId(id);

        Product productFound = productService.getById(productId);
        if (productFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Product ID");
        }

        Godown godownFound = godownService.getById(godownId);
        if (godownFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Godown ID");
        }

        Supplier supplierFound = supplierService.getById(supplierId);
        if (supplierFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Supplier ID");
        }

        inward.setProduct(productFound);
        inward.setGodown(godownFound);
        inward.setSupplier(supplierFound);

        inward.setDateOfSupply(inward.getDateOfSupply());

        inward = inwardService.insert(inward);
        return ResponseEntity.status(HttpStatus.OK).body(inward);
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> delete(@PathVariable int id) {
        Inward inwardFound = inwardService.getById(id);

        if (inwardFound == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Id");
        }

        inwardService.delete(inwardFound);
        return ResponseEntity.status(HttpStatus.OK).body("Deleted....");
    }

    @GetMapping("/report")
    public List<InwardDto> inwardReport() {
        List<Inward> list = inwardService.getAll();
        List<InwardDto> listDto = new ArrayList<>();
        list.stream().forEach(entry -> {
            InwardDto dto = new InwardDto();
            dto.setProductTitle(entry.getProduct().getTitle());
            dto.setProductQuantity(entry.getQuantity());
            dto.setGodownLocation(entry.getGodown().getLocation());
            dto.setGodownManager(entry.getGodown().getManager().getName());
            dto.setSupplierName(entry.getSupplier().getName());
            dto.setSupplierCity(entry.getSupplier().getCity());
            dto.setQuantity(entry.getQuantity());
            dto.setInvoiceNumber(entry.getInvoiceNumber());
            dto.setReceiptNo(entry.getRecieptNo());
            dto.setDateOfSupply(entry.getDateOfSupply());
            listDto.add(dto);
        });

        return listDto;
    }

    @GetMapping("/report/supplier/{supplierId}")
    public ResponseEntity<?> inwardReportBySupplier(@PathVariable int supplierId) {
        List<Inward> list;
        try {
            list = inwardService.getBySupplierId(supplierId);
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }

        List<InwardBySupplierDto> listDto = new ArrayList<>();
        list.stream().forEach(entry -> {
            InwardBySupplierDto dto = new InwardBySupplierDto();
            dto.setProductTitle(entry.getProduct().getTitle());
            dto.setProductQuantity(entry.getQuantity());
            dto.setProductPrice(entry.getProduct().getPrice());
            dto.setSupplierName(entry.getSupplier().getName());
            dto.setSupplierCity(entry.getSupplier().getCity());
            dto.setQuantity(entry.getQuantity());
            dto.setInvoiceNumber(entry.getInvoiceNumber());
            dto.setReceiptNo(entry.getRecieptNo());
            dto.setDateOfSupply(entry.getDateOfSupply());
            listDto.add(dto);
        });

        return ResponseEntity.status(HttpStatus.OK).body(listDto);
    }

}
