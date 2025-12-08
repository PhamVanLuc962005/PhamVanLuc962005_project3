package com.MaxSport.PhamVanLuc_2310900059_Project3.repository;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.DanhMuc;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface DanhMucRepository extends JpaRepository<DanhMuc, Integer> {

    // Lấy các danh mục cha (không có cha) để hiển thị menu cấp 1
    List<DanhMuc> findByDanhMucChaIsNull();
}