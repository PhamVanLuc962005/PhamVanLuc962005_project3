package com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request;

import lombok.Data;
import java.util.List;

@Data
public class DatHangRequest {
    private String diaChiGiaoHang;
    private String soDienThoai;
    private String phuongThucThanhToan; // COD, VNPAY...
    private String maGiamGia;

    // Danh sách các món hàng muốn mua
    private List<ChiTietDatHangRequest> danhSachSanPham;
}