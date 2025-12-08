package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.SanPhamPhienBan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface SanPhamPhienBanRepository extends JpaRepository<SanPhamPhienBan, Long> {
    // Lấy tất cả phiên bản của 1 sản phẩm
    List<SanPhamPhienBan> findBySanPhamId(Long sanPhamId);
}