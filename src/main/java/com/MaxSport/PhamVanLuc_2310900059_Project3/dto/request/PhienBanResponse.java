package com.MaxSport.PhamVanLuc_2310900059_Project3.dto.response;

import lombok.Data;
import java.math.BigDecimal;

@Data
public class PhienBanResponse {
    private Long id;
    private String maSku;
    private BigDecimal giaBan;
    private String thuocTinh; // JSON String (Size, Mau...)
}