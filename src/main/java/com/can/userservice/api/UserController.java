package com.can.userservice.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.can.userservice.model.Role;
import com.can.userservice.model.User;
import com.can.userservice.results.DataResult;
import com.can.userservice.results.Result;
import com.can.userservice.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import java.net.URI;
import java.util.*;
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@CrossOrigin("*")
public class UserController {

    private final UserService userService;


    @GetMapping("/users")
    public ResponseEntity<DataResult<List<User>>> getUsers(){
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @GetMapping("/roles")
    public ResponseEntity<DataResult<List<Role>>> getRoles(){
        return ResponseEntity.ok().body(userService.getRoles());
    }


    @PostMapping("/user/save")
    public ResponseEntity<DataResult<User>> saveUser(@RequestBody User user){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        return ResponseEntity.created(uri).body(userService.save(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<DataResult<Role>> saveRole(@RequestBody Role role){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());

        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }
    @PostMapping("/role/addtouser")
    public ResponseEntity<Result> addRoleToUser(@RequestBody RoleToUserForm form){
        userService.addRoleToUser(form.getUserName(),form.getRoleName());
        return ResponseEntity.ok().build();
    }


}



@Data
class RoleToUserForm{
    private  String userName;
    private String roleName;
}
