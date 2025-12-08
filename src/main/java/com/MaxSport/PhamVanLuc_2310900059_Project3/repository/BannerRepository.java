package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.Banner;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface BannerRepository extends JpaRepository<Banner, Integer> {
    // Lấy danh sách banner đang kích hoạt để hiển thị trang chủ
    List<Banner> findByKichHoatTrueOrderByUuTienDesc();
}