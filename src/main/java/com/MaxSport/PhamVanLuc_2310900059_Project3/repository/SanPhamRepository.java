package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.SanPham;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

@Repository
public interface SanPhamRepository extends JpaRepository<SanPham, Long> {

    // Tìm sản phẩm đang hiển thị (Trả về List thường)
    List<SanPham> findByHienThiTrue();

    // Tìm kiếm theo tên gần đúng (Trả về List thường)
    List<SanPham> findByTenContaining(String keyword);

    // Query phức tạp: Lấy 10 sản phẩm mới nhất
    @Query(value = "SELECT * FROM san_pham WHERE hien_thi = true ORDER BY ngay_tao DESC LIMIT 10", nativeQuery = true)
    List<SanPham> findTop10Newest();

    // 1. Tìm kiếm theo tên (Có phân trang Page)
    // Containing: Tìm gần đúng (LIKE %...%)
    // IgnoreCase: Không phân biệt hoa thường (a = A)
    Page<SanPham> findByTenContainingIgnoreCaseAndHienThiTrue(String ten, Pageable pageable);

    // 2. Lấy danh sách hiển thị (Có phân trang Page)
    Page<SanPham> findByHienThiTrue(Pageable pageable);

    @Query("SELECT p FROM SanPham p WHERE " +
            "(:keyword IS NULL OR LOWER(p.ten) LIKE LOWER(CONCAT('%', :keyword, '%'))) AND " +
            "(:categoryId IS NULL OR p.danhMuc.id = :categoryId) AND " +
            "p.hienThi = true")
    Page<SanPham> timKiemVaLoc(@Param("keyword") String keyword,
                               @Param("categoryId") Integer categoryId,
                               Pageable pageable);

}