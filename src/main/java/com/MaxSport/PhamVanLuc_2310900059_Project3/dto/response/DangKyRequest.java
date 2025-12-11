package com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DangKyRequest {
    private String tenDangNhap;
    private String password; // Mật khẩu chưa mã hóa
    private String email;
    private String soDienThoai;
    private String hoTen;
    private String diaChi;
}