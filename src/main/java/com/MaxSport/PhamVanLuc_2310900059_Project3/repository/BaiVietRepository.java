package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.BaiViet;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface BaiVietRepository extends JpaRepository<BaiViet, Long> {
    // Tìm bài viết theo slug (Ví dụ: cach-chon-giay)
    Optional<BaiViet> findByDuongDan(String duongDan);
}