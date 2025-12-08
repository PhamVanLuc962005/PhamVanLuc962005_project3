package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.HinhAnhDanhGia;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface HinhAnhDanhGiaRepository extends JpaRepository<HinhAnhDanhGia, Long> {
}