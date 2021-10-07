package com.can.userservice.service;

import com.can.userservice.model.Role;
import com.can.userservice.model.User;
import com.can.userservice.repository.RoleRepository;
import com.can.userservice.repository.UserRepository;
import com.can.userservice.results.DataResult;
import com.can.userservice.results.Result;
import com.can.userservice.results.SuccessDataResult;
import com.can.userservice.results.SuccessResult;
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
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new org.springframework.security.core.userdetails.User(user.getName(),user.getPassword(),authorities);
    }
    @Override
    public DataResult<User> save(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return new SuccessDataResult<User>(userRepository.save(user)) ;
//        log.info("Veritabanına yeni bir kullanıcı eklendi {}",user.getName());
    }

    @Override
    public DataResult<Role> saveRole(Role role) {
       // log.info("Veritabanına yeni bir rol eklendi {}",role.getName());
        return new SuccessDataResult<Role>(roleRepository.save(role)) ;
    }

    @Override
    public Result addRoleToUser(String userName, String roleName) {
      //  log.info("{} adlı kullanıcıya yeni bir role atandı {}", userName ,roleName);
        User user = userRepository.findByUserName(userName);
        Role role = roleRepository.findByName(roleName);
        user.getRoles().add(role);
        return new SuccessResult("Kullancıya yeni rol atandı");
    }

    @Override
    public DataResult<User> getUser(String userName) {
       // log.info("Kullanıcı getirildi {}",userName);
        return new SuccessDataResult<User>(userRepository.findByUserName(userName)) ;
    }

    @Override
    public DataResult<List<User>> getUsers() {
      //  log.info("Kullanıcılar getirildi ");
        return new SuccessDataResult<List<User>>(userRepository.findAll()) ;
    }

    @Override
    public DataResult<List<Role>> getRoles() {
        //  log.info("Kullanıcılar getirildi ");
        return new SuccessDataResult<List<Role>>(roleRepository.findAll()) ;
    }

}
