package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.PhanHoiKhieuNai;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface PhanHoiKhieuNaiRepository extends JpaRepository<PhanHoiKhieuNai, Long> {
    List<PhanHoiKhieuNai> findByKhieuNaiIdOrderByThoiGianAsc(Long khieuNaiId);
}