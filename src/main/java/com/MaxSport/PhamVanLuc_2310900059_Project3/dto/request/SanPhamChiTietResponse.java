package com.MaxSport.PhamVanLuc_2310900059_Project3.dto.response;

import lombok.Data;
import java.math.BigDecimal;
import java.util.List;

@Data
public class SanPhamChiTietResponse {
    private Long id;
    private String ten;
    private String maSku;
    private String tenThuongHieu;
    private String tenDanhMuc;
    private String moTaChiTiet;
    private BigDecimal giaGoc;
    private String hinhAnh;


    private List<PhienBanResponse> danhSachPhienBan;
}