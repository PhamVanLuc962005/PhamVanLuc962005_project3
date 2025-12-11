package com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request;

import lombok.Data;
import java.math.BigDecimal;

@Data
public class SanPhamRequest {
    private String ten;
    private String maSku;
    private Integer idThuongHieu; // Chỉ cần gửi ID
    private Integer idDanhMuc;    // Chỉ cần gửi ID
    private String moTaNgan;
    private String moTaChiTiet;
    private BigDecimal giaGoc;
    private Boolean hienThi;
}