package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.TuKhoaTimKiem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface TuKhoaTimKiemRepository extends JpaRepository<TuKhoaTimKiem, Integer> {
    // Lấy lịch sử tìm kiếm của người dùng
    List<TuKhoaTimKiem> findByNguoiDungIdOrderByThoiGianTimDesc(Long nguoiDungId);
}