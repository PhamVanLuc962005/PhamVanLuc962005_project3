package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.NguoiDung;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface NguoiDungRepository extends JpaRepository<NguoiDung, Long> {

    // Tìm user bằng Email để đăng nhập (Thay vì tên đăng nhập)
    Optional<NguoiDung> findByEmail(String email);

    // Kiểm tra trùng email (Bắt buộc phải duy nhất)
    Boolean existsByEmail(String email);

    // Tìm theo tên đăng nhập (Giữ lại nếu cần hiển thị profile, nhưng không dùng để login)
    Optional<NguoiDung> findByTenDangNhap(String tenDangNhap);
}