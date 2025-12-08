package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.DonHang;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

@Repository
public interface DonHangRepository extends JpaRepository<DonHang, Long> {
    // Lấy lịch sử mua hàng của người dùng
    List<DonHang> findByNguoiDungId(Long nguoiDungId);

    // Tìm đơn hàng theo mã đơn (VD: ORD-12345)
    Optional<DonHang> findByMaDon(String maDon);

    // COALESCE(SUM(...), 0) nghĩa là: Nếu không có đơn nào thì trả về 0 thay vì null
    @Query("SELECT COALESCE(SUM(d.tongTien), 0) FROM DonHang d")
    BigDecimal tinhTongDoanhThu();

    // Đếm số lượng đơn hàng theo trạng thái (Ví dụ: Đếm xem có bao nhiêu đơn đang CHO_XU_LY)
    Long countByTrangThai(String trangThai);

}