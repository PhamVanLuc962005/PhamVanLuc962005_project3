package com.MaxSport.PhamVanLuc_2310900059_Project3.controller;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.MaGiamGia;
import com.MaxSport.PhamVanLuc_2310900059_Project3.service.MaGiamGiaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/ma-giam-gia")
public class MaGiamGiaController {

    @Autowired
    private MaGiamGiaService maGiamGiaService;

    // Admin: Lấy danh sách
    @GetMapping
    public ResponseEntity<?> getAll() {
        return ResponseEntity.ok(maGiamGiaService.layTatCa());
    }

    // Admin: Tạo mã
    @PostMapping
    public ResponseEntity<?> create(@RequestBody MaGiamGia maGiamGia) {
        return ResponseEntity.ok(maGiamGiaService.luuMaGiamGia(maGiamGia));
    }

    // Admin: Xóa mã
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        maGiamGiaService.xoaMa(id);
        return ResponseEntity.ok("Đã xóa mã giảm giá");
    }
    @GetMapping("/kiem-tra")
    public ResponseEntity<?> checkCoupon(@RequestParam String code, @RequestParam Long total) {
        MaGiamGia voucher = maGiamGiaService.timTheoMa(code);

        if (voucher == null) return ResponseEntity.badRequest().body("Mã giảm giá không tồn tại!");
        if (voucher.getKetThuc().isBefore(LocalDateTime.now())) return ResponseEntity.badRequest().body("Mã đã hết hạn!");
        if (voucher.getGioiHan() != null && voucher.getSoLanDung() >= voucher.getGioiHan()) return ResponseEntity.badRequest().body("Mã đã hết lượt sử dụng!");
        if (BigDecimal.valueOf(total).compareTo(voucher.getDonToiThieu()) < 0) return ResponseEntity.badRequest().body("Đơn hàng chưa đạt giá trị tối thiểu!");

        // Tính tiền giảm
        BigDecimal giamGia = BigDecimal.ZERO;
        if ("tien_mat".equals(voucher.getLoai())) {
            giamGia = voucher.getGiaTri();
        } else {
            giamGia = BigDecimal.valueOf(total).multiply(voucher.getGiaTri()).divide(BigDecimal.valueOf(100));
        }

        // Trả về số tiền được giảm
        return ResponseEntity.ok(giamGia);
    }
}