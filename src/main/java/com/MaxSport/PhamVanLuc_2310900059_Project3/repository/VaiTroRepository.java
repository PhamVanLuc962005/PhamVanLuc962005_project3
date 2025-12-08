package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.VaiTro;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface VaiTroRepository extends JpaRepository<VaiTro, Integer> {
    // Tìm vai trò theo tên (ví dụ: tìm role "USER" để gán cho người mới đăng ký)
    Optional<VaiTro> findByTen(String ten);
}