package com.MaxSport.PhamVanLuc_2310900059_Project3.controller;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.PhienBanRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.SanPhamRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.SanPham;
import com.MaxSport.PhamVanLuc_2310900059_Project3.service.SanPhamService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/san-pham")
public class SanPhamController {

    @Autowired
    private SanPhamService sanPhamService;

    // API lấy danh sách
    @GetMapping
    public ResponseEntity<Page<SanPham>> getAll(
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) Integer categoryId,
            @RequestParam(defaultValue = "0") Integer page,
            @RequestParam(defaultValue = "10") Integer size
    ) {
        return ResponseEntity.ok(sanPhamService.layDanhSachSanPham(keyword, categoryId, page, size));
    }

    // API Thêm mới
    @PostMapping
    public ResponseEntity<?> create(@RequestBody SanPhamRequest request) {
        return ResponseEntity.ok(sanPhamService.themSanPham(request));
    }

    // API Thêm phiên bản
    @PostMapping("/{id}/phien-ban")
    public ResponseEntity<?> addVersion(@PathVariable Long id, @RequestBody PhienBanRequest request) {
        return ResponseEntity.ok(sanPhamService.themPhienBan(id, request));
    }

    // API Xem chi tiết
    @GetMapping("/{id}")
    public ResponseEntity<?> getDetail(@PathVariable Long id) {
        return ResponseEntity.ok(sanPhamService.layChiTietSanPham(id));
    }

    // API Upload ảnh
    @PostMapping("/{id}/hinh-anh")
    public ResponseEntity<?> uploadImage(@PathVariable Long id, @RequestParam("file") MultipartFile file) {
        return ResponseEntity.ok(sanPhamService.themHinhAnh(id, file));
    }
    // API Sửa sản phẩm
    @PutMapping("/{id}")
    public ResponseEntity<?> update(@PathVariable Long id, @RequestBody SanPhamRequest request) {
        return ResponseEntity.ok(sanPhamService.capNhatSanPham(id, request));
    }

    // API Xóa sản phẩm
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        sanPhamService.xoaSanPham(id);
        return ResponseEntity.ok("Đã xóa sản phẩm thành công");
    }
}