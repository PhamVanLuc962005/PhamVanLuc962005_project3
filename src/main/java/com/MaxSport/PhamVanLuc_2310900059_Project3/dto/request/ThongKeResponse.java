package com.MaxSport.PhamVanLuc_2310900059_Project3.dto.response;

import lombok.Builder;
import lombok.Data;
import java.math.BigDecimal;

@Data
@Builder
public class ThongKeResponse {
    private BigDecimal tongDoanhThu;
    private Long tongSoDonHang;
    private Long soDonChoXuLy;
    private Long soDonDangGiao;
    private Long soDonHoanThanh;
    private Long tongSoNguoiDung;
    private Long tongSoSanPham;
}