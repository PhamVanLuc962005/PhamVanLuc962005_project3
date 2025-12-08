package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.TonKho;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface TonKhoRepository extends JpaRepository<TonKho, Long> {
    // Kiểm tra tồn kho của một phiên bản sản phẩm trong 1 kho cụ thể
    Optional<TonKho> findByKhoHangIdAndSanPhamPhienBanId(Integer khoId, Long phienBanId);
}