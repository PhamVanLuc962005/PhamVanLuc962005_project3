package com.MaxSport.PhamVanLuc_2310900059_Project3.service;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.MaGiamGia;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.MaGiamGiaRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MaGiamGiaService {

    @Autowired
    private MaGiamGiaRepository maGiamGiaRepository;

    // 1. Lấy tất cả mã (Mới nhất lên đầu)
    public List<MaGiamGia> layTatCa() {
        return maGiamGiaRepository.findAll(Sort.by(Sort.Direction.DESC, "id"));
    }
    // 2. Thêm mới / Cập nhật
    public MaGiamGia luuMaGiamGia(MaGiamGia maGiamGia) {
        // Kiểm tra trùng mã nếu cần (Ở đây làm đơn giản)
        if (maGiamGia.getSoLanDung() == null) maGiamGia.setSoLanDung(0);
        return maGiamGiaRepository.save(maGiamGia);
    }
    // 3. Xóa mã
    public void xoaMa(Long id) {
        maGiamGiaRepository.deleteById(id);
    }
    public MaGiamGia timTheoMa(String ma) {
        return maGiamGiaRepository.findByMa(ma).orElse(null);
    }
}