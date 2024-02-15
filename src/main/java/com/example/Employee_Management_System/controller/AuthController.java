package com.example.Employee_Management_System.controller;

import com.example.Employee_Management_System.domain.User;
import com.example.Employee_Management_System.dto.request.CheckEmailExistRequest;
import com.example.Employee_Management_System.dto.request.GoogleLoginRequest;
import com.example.Employee_Management_System.dto.request.LoginRequest;
import com.example.Employee_Management_System.dto.request.RegisterRequest;
import com.example.Employee_Management_System.dto.request.UpdateProfileRequest;
import com.example.Employee_Management_System.dto.response.Response;
import com.example.Employee_Management_System.dto.response.UserInformation;
import com.example.Employee_Management_System.service.AuthService;
import com.example.Employee_Management_System.service.JwtService;
import com.example.Employee_Management_System.service.UserService;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.UnsupportedEncodingException;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", allowedHeaders = "*")
@AllArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserService userService;
    private final JwtService jwtService;
    private final Logger logger = LoggerFactory.getLogger(AuthController.class);
    @PostMapping("/register-account")
    public ResponseEntity<Response> register(@RequestBody RegisterRequest registerRequest) throws UnsupportedEncodingException, MessagingException {
        return authService.register(registerRequest);
    }

    @PostMapping("/exists-email")
    public ResponseEntity<Response> existsEmail(@RequestBody CheckEmailExistRequest request) {
        return authService.existsEmail(request);
    }

    @GetMapping("/verify/{code}")
    public ResponseEntity<Response> verify(@PathVariable String code) {
        logger.info("verify");
        return ResponseEntity.ok(
                Response.builder()
                        .data(authService.verify(code))
                        .status(200)
                        .message("Verify successfully!")
                        .build());
    }


    @PostMapping("/login")
    public ResponseEntity<Response> login(@RequestBody LoginRequest loginRequest) {
        logger.info("logging in");
        return authService.formLogin(loginRequest);
    }

    @GetMapping("/get-manager-info/{referencedCode}")
    public ResponseEntity<Response> getManagerInfo(@PathVariable String referencedCode) {
        return authService.getManagerInfo(referencedCode);
    }

    @PostMapping("/google-login")
    public ResponseEntity<Response> googleLogin(@RequestBody GoogleLoginRequest loginRequest) {
        return authService.googleLogin(loginRequest);
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/register-account/manager")
    public ResponseEntity<Response> registerManager(HttpServletRequest request) {
        return authService.selectRoleManager(getCurrentUser(request));
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/register-account/employee/{referenceCode}")
    public ResponseEntity<Response> registerEmployee(@PathVariable String referenceCode, HttpServletRequest request) {
        User user = getCurrentUser(request);
        return ResponseEntity.ok(
                Response.builder()
                        .data(authService.selectRoleEmployee(user, referenceCode))
                        .status(200)
                        .message("Register employee successfully!")
                        .build());
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/user-info")
    public ResponseEntity<Response> userInfo(HttpServletRequest request) {
        UserInformation userInformation = userService.getUserInfo(getCurrentUser(request));
        log.warn("User information: {}", userInformation);
        return ResponseEntity.ok(
                Response.builder()
                        .data(userInformation)
                        .status(200)
                        .message("Get user information successfully!")
                        .build());
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/change-avatar")
    public ResponseEntity<Response> changeAvatar(@RequestParam("file") MultipartFile file, HttpServletRequest request) {
        User user = getCurrentUser(request);
        return ResponseEntity.ok(
                Response.builder()
                        .data(userService.changeAvatar(user, file))
                        .status(200)
                        .message("Upload avatar successfully")
                        .build());
    }

    private User getCurrentUser(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("authorization");
        String jwt = authorizationHeader.substring(7);
        String email = jwtService.extractEmail(jwt);
        User user = userService.getUserByEmail(email);
        log.warn("User: {}", user);
        return user;
    }

    @PreAuthorize("isAuthenticated()")
    @PutMapping(value = "/update-user-info")
    public ResponseEntity<Response> updateUserInfo(@RequestBody UpdateProfileRequest updateProfileRequest, HttpServletRequest request) {
        User user = getCurrentUser(request);
        return ResponseEntity.ok(
                Response.builder()
                        .data(userService.updateUserInfo(user, updateProfileRequest))
                        .status(200)
                        .message("Update user information successfully")
                        .build()
        );
    }
}
