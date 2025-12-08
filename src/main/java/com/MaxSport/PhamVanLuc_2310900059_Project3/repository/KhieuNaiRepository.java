package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.KhieuNai;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface KhieuNaiRepository extends JpaRepository<KhieuNai, Long> {
    List<KhieuNai> findByNguoiDungId(Long nguoiDungId);
}