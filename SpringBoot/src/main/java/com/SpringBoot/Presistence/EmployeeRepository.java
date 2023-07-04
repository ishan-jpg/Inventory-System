package com.SpringBoot.Presistence;

import org.springframework.data.jpa.repository.JpaRepository;

import com.inventory.main.models.Employee;

public interface EmployeeRepository extends JpaRepository<Employee, Integer>{

}
