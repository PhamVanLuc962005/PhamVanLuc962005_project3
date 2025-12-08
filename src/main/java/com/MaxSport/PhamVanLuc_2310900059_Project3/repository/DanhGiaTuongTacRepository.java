package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.DanhGiaTuongTac;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface DanhGiaTuongTacRepository extends JpaRepository<DanhGiaTuongTac, Long> {
    // Kiểm tra xem user đã like/dislike đánh giá này chưa
    Optional<DanhGiaTuongTac> findByDanhGiaIdAndNguoiDungId(Long danhGiaId, Long nguoiDungId);
}