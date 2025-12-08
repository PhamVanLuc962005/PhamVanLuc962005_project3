package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.ThanhToan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface ThanhToanRepository extends JpaRepository<ThanhToan, Long> {
    Optional<ThanhToan> findByDonHangId(Long donHangId);
}