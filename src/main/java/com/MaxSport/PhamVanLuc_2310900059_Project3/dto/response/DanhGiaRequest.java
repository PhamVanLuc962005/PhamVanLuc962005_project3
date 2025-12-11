package com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request;

import lombok.Data;

@Data
public class DanhGiaRequest {
    private Long idSanPham;
    private Integer diem; // 1 đến 5 sao
    private String tieuDe;
    private String noiDung;
}