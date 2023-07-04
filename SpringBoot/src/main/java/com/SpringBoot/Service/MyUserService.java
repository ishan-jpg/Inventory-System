package com.SpringBoot.Service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.inventory.main.models.User;
import com.inventory.main.persistence.UserRepository;

@Service
public class MyUserService implements UserDetailsService {

    @Autowired
    public UserRepository userRepository;

    public User insert(User user) {
        return userRepository.save(user);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.getByUsername(username);

        return user;
    }

}

