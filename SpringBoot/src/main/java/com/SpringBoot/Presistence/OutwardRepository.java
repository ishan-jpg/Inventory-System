package com.SpringBoot.Presistence;

import org.springframework.data.jpa.repository.JpaRepository;

import com.inventory.main.models.Outward;

public interface OutwardRepository extends JpaRepository<Outward, Integer>{

}
