package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.SanPhamHinhAnh;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface SanPhamHinhAnhRepository extends JpaRepository<SanPhamHinhAnh, Long> {
    List<SanPhamHinhAnh> findBySanPhamId(Long sanPhamId);
}