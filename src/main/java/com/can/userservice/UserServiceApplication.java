package com.can.userservice;

import com.can.userservice.model.Role;
import com.can.userservice.model.User;
import com.can.userservice.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.ArrayList;

@SpringBootApplication
@EnableSwagger2
public class UserServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(UserServiceApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .select()
                .apis(RequestHandlerSelectors.any())
                .paths(PathSelectors.any())
                .build();

    }
//        @Bean
//    public WebMvcConfigurer corsConfigurer() {
//            return new WebMvcConfigurerAdapter() {
//            @Override
//            public void addCorsMappings(CorsRegistry registry) {
//                registry.addMapping("/**").allowedOrigins("http://localhost:4200").allowCredentials(true);
//            }
//        };
//    }

//    @Bean
//    CommandLineRunner run(UserService userService){
//        return args -> {
//          userService.saveRole(new Role(null,"ROLE_USER"));
//          userService.saveRole(new Role(null,"ROLE_MANAGER"));
//          userService.saveRole(new Role(null,"ROLE_ADMIN"));
//          userService.saveRole(new Role(null,"ROLE_SUPER_ADMIN"));
//
//          userService.save(new User(null,"Can Ozyigit","can","123456", new ArrayList<>()));
//          userService.save(new User(null,"Jim Carry","jim","123456", new ArrayList<>()));
//          userService.save(new User(null,"Will Smith","will","123456", new ArrayList<>()));
//          userService.save(new User(null,"Rihanna","rihanna","123456", new ArrayList<>()));
//
//          userService.addRoleToUser("can","ROLE_SUPER_ADMIN");
//          userService.addRoleToUser("can","ROLE_ADMIN");
//          userService.addRoleToUser("can","ROLE_MANAGER");
//          userService.addRoleToUser("can","ROLE_USER");
//          userService.addRoleToUser("jim","ROLE_MANAGER");
//          userService.addRoleToUser("will","ROLE_ADMIN");
//          userService.addRoleToUser("rihanna","ROLE_USER");
//        };
//    }


}
