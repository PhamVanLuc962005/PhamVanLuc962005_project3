package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.DanhGia;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface DanhGiaRepository extends JpaRepository<DanhGia, Long> {
    // Lấy đánh giá của một sản phẩm
    List<DanhGia> findBySanPhamId(Long sanPhamId);
}