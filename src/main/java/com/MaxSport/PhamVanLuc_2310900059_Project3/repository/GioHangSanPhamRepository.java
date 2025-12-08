package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.GioHang;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.GioHangSanPham;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface GioHangSanPhamRepository extends JpaRepository<GioHangSanPham, Long> {
    // Xóa tất cả chi tiết theo Giỏ Hàng
    void deleteByGioHang(GioHang gioHang);
}