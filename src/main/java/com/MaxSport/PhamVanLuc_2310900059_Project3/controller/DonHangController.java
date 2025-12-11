package com.MaxSport.PhamVanLuc_2310900059_Project3.controller;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.DatHangRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.DonHang;
import com.MaxSport.PhamVanLuc_2310900059_Project3.service.DonHangService;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.DonHangRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/don-hang")
public class DonHangController {

    @Autowired
    private DonHangService donHangService;

    @Autowired
    private DonHangRepository donHangRepository;

    @PostMapping("/dat-hang")
    public ResponseEntity<?> placeOrder(@RequestBody DatHangRequest request) {
        return ResponseEntity.ok(donHangService.taoDonHang(request));
    }

    @GetMapping("/cua-toi")
    public ResponseEntity<List<DonHang>> getMyOrders() {
        return ResponseEntity.ok(donHangService.layLichSuDonHang());
    }

    // API cho Admin xem tất cả đơn
    @GetMapping("/quan-ly")
    public ResponseEntity<List<DonHang>> getAllOrders() {
        return ResponseEntity.ok(donHangService.layTatCaDonHang());
    }

    // API cho Admin duyệt đơn/hủy đơn
    @PutMapping("/quan-ly/{id}/trang-thai")
    public ResponseEntity<?> updateStatus(@PathVariable Long id, @RequestParam String status) {
        return ResponseEntity.ok(donHangService.capNhatTrangThai(id, status));
    }
    @GetMapping("/quan-ly/nguoi-dung/{id}")
    public ResponseEntity<List<DonHang>> getOrdersByUserId(@PathVariable Long id) {
        // Tận dụng hàm findByNguoiDungId có sẵn trong Repository
        return ResponseEntity.ok(donHangRepository.findByNguoiDungId(id));
    }
}