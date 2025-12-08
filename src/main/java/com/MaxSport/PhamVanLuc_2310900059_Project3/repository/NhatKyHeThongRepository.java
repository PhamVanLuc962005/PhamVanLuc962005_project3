package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.NhatKyHeThong;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface NhatKyHeThongRepository extends JpaRepository<NhatKyHeThong, Long> {
    // Xem nhật ký hoạt động của 1 nhân viên cụ thể
    List<NhatKyHeThong> findByThucHienBoi(Long userId);
}