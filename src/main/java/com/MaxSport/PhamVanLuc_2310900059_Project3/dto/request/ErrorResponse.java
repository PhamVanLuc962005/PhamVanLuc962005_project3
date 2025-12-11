package com.MaxSport.PhamVanLuc_2310900059_Project3.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ErrorResponse {
    private LocalDateTime timestamp; // Thời gian xảy ra lỗi
    private int status;              // Mã lỗi (400, 404, 500...)
    private String error;            // Tên lỗi
    private String message;          // Chi tiết lỗi (User already exists...)
}