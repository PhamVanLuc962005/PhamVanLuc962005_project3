package com.MaxSport.PhamVanLuc_2310900059_Project3.controller;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.CapNhatThongTinRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.DoiMatKhauRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.NguoiDung;
import com.MaxSport.PhamVanLuc_2310900059_Project3.service.NguoiDungService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.context.SecurityContextHolder;

@RestController
@RequestMapping("/api/nguoi-dung")
public class NguoiDungController {

    @Autowired
    private NguoiDungService nguoiDungService;

    @Autowired
    private com.MaxSport.PhamVanLuc_2310900059_Project3.repository.NguoiDungRepository nguoiDungRepository;

    // API Cập nhật thông tin (Họ tên, địa chỉ...)
    @PutMapping("/thong-tin")
    public ResponseEntity<?> updateInfo(@RequestBody CapNhatThongTinRequest request) {
        NguoiDung updatedUser = nguoiDungService.capNhatThongTin(request);
        return ResponseEntity.ok("Cập nhật thông tin thành công!");
    }

    // API Đổi mật khẩu
    @PutMapping("/doi-mat-khau")
    public ResponseEntity<?> changePassword(@RequestBody DoiMatKhauRequest request) {
        nguoiDungService.doiMatKhau(request);
        return ResponseEntity.ok("Đổi mật khẩu thành công!");
    }

    @GetMapping("/my-info")
    public ResponseEntity<?> getMyInfo() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        NguoiDung user = nguoiDungRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return ResponseEntity.ok(user);
    }
    @GetMapping("/quan-ly")
    public ResponseEntity<Page<NguoiDung>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        return ResponseEntity.ok(nguoiDungService.layDanhSachNguoiDung(page, size));
    }

    // API Khóa/Mở khóa (Admin)
    @PutMapping("/quan-ly/{id}/trang-thai")
    public ResponseEntity<?> toggleStatus(@PathVariable Long id) {
        nguoiDungService.doiTrangThaiKichHoat(id);
        return ResponseEntity.ok("Đã thay đổi trạng thái người dùng!");
    }
    @GetMapping("/quan-ly/{id}")
    public ResponseEntity<?> getUserDetail(@PathVariable Long id) {
        NguoiDung user = nguoiDungRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Người dùng không tồn tại"));
        return ResponseEntity.ok(user);
    }
}