package com.MaxSport.PhamVanLuc_2310900059_Project3.controller;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.PhanHoiRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.service.KhieuNaiService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/khieu-nai")
public class KhieuNaiController {

    @Autowired
    private KhieuNaiService khieuNaiService;

    // --- USER ---
    // Tạo khiếu nại (kèm ảnh)
    @PostMapping("/tao")
    public ResponseEntity<?> createTicket(
            @RequestParam Long idDonHang,
            @RequestParam String noiDung,
            @RequestParam(value = "file", required = false) MultipartFile file) {
        return ResponseEntity.ok(khieuNaiService.taoKhieuNai(idDonHang, noiDung, file));
    }

    // Xem lịch sử khiếu nại cá nhân
    @GetMapping("/cua-toi")
    public ResponseEntity<?> getMyTickets() {
        return ResponseEntity.ok(khieuNaiService.layKhieuNaiCuaToi());
    }

    // --- ADMIN ---
    // Xem tất cả
    @GetMapping("/quan-ly")
    public ResponseEntity<?> getAllTickets() {
        return ResponseEntity.ok(khieuNaiService.layTatCaKhieuNai());
    }

    // Cập nhật trạng thái (VD: Dang xu ly, Hoan thanh, Tu choi)
    @PutMapping("/quan-ly/{id}/trang-thai")
    public ResponseEntity<?> updateStatus(@PathVariable Long id, @RequestParam String status) {
        return ResponseEntity.ok(khieuNaiService.capNhatTrangThai(id, status));
    }

    // --- CHUNG (CHAT) ---
    // Gửi câu trả lời
    @PostMapping("/{id}/phan-hoi")
    public ResponseEntity<?> reply(@PathVariable Long id, @RequestBody PhanHoiRequest request) {
        return ResponseEntity.ok(khieuNaiService.guiPhanHoi(id, request));
    }

    // Xem lịch sử chat
    @GetMapping("/{id}/phan-hoi")
    public ResponseEntity<?> getConversation(@PathVariable Long id) {
        return ResponseEntity.ok(khieuNaiService.layHoiThoai(id));
    }
}