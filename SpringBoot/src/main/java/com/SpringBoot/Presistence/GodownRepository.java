package com.SpringBoot.Presistence;

import org.springframework.data.jpa.repository.JpaRepository;

import com.inventory.main.models.Godown;

public interface GodownRepository extends JpaRepository<Godown, Integer>{

}
