package com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request;

import lombok.Data;
import java.math.BigDecimal;

@Data
public class PhienBanRequest {
    private String maSkuPhienBan;
    private BigDecimal giaBan;
    private BigDecimal khoiLuong;

    // Thuộc tính lưu dưới dạng chuỗi JSON
    // Ví dụ: "{\"size\": \"M\", \"mau\": \"Do\"}"
    private String thuocTinh;
}