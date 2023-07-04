package com.SpringBoot.Service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.inventory.main.models.Employee;
import com.inventory.main.persistence.EmployeeRepository;

@Service
public class EmployeeService {
    @Autowired
    private EmployeeRepository employeeRepository;

    public Employee insert(Employee employee) {
        return employeeRepository.save(employee);
    }
}
