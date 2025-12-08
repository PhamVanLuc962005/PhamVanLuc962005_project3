package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.GioHang;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface GioHangRepository extends JpaRepository<GioHang, Long> {
    // Tìm giỏ hàng của người dùng
    Optional<GioHang> findByNguoiDungId(Long nguoiDungId);
}