package com.can.userservice.service;

import com.can.userservice.model.Role;
import com.can.userservice.model.User;
import com.can.userservice.repository.RoleRepository;
import com.can.userservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;


@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;


    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        User user = userRepository.findByUserName(userName);
        if (user == null){
            log.error("Kullanıcı bulunamadı");
            throw new UsernameNotFoundException("Kullanıcı bulunamadı");
        }else {
            log.error("Kullanıcı bulundu: {}",userName);
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new org.springframework.security.core.userdetails.User(user.getName(),user.getPassword(),authorities);
    }
    @Override
    public User save(User user) {
        log.info("Veritabanına yeni bir kullanıcı eklendi {}",user.getName());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Veritabanına yeni bir rol eklendi {}",role.getName());
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String userName, String roleName) {
        log.info("{} adlı kullanıcıya yeni bir role atandı {}", userName ,roleName);
        User user = userRepository.findByUserName(userName);
        Role role = roleRepository.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public User getUser(String userName) {
        log.info("Kullanıcı getirildi {}",userName);
        return userRepository.findByUserName(userName);
    }

    @Override
    public List<User> getUsers() {
        log.info("Kullanıcılar getirildi ");
        return userRepository.findAll();
    }

}
