package com.MaxSport.PhamVanLuc_2310900059_Project3.controller;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.DangKyRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.DangNhapRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.response.JwtResponse;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.NguoiDung;
import com.MaxSport.PhamVanLuc_2310900059_Project3.service.NguoiDungService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private NguoiDungService nguoiDungService;

    @PostMapping("/register")
    public ResponseEntity<?> dangKy(@RequestBody DangKyRequest request) {
        NguoiDung newUser = nguoiDungService.dangKyNguoiDung(request);
        return ResponseEntity.ok("Đăng ký thành công tài khoản: " + newUser.getTenDangNhap());
    }

    @PostMapping("/login")
    public ResponseEntity<?> dangNhap(@RequestBody DangNhapRequest request) {
        // GlobalExceptionHandler sẽ tự xử lý nếu sai pass hoặc không tìm thấy user
        JwtResponse response = nguoiDungService.dangNhap(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile() {
        return ResponseEntity.ok("Xin chào, đây là thông tin bí mật chỉ user đăng nhập mới thấy!");
    }
}