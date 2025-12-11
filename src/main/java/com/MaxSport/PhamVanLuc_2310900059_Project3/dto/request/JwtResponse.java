package com.MaxSport.PhamVanLuc_2310900059_Project3.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JwtResponse {
    private String token;
    private String tenDangNhap;
    private String quyen; // ROLE_USER hoặc ROLE_ADMIN
}