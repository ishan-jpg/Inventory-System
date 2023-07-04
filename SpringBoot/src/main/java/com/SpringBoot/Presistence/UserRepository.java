package com.SpringBoot.Presistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.inventory.main.models.User;

public interface UserRepository extends JpaRepository<User, Integer>{

    @Query("select u from User u where u.username = ?1")
    User getByUsername(String username);
}
