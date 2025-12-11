package com.MaxSport.PhamVanLuc_2310900059_Project3.controller;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.BaiVietRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.service.BaiVietService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/bai-viet")
public class BaiVietController {

    @Autowired
    private BaiVietService baiVietService;

    // Public: Xem danh sách
    @GetMapping
    public ResponseEntity<?> getAll() {
        return ResponseEntity.ok(baiVietService.layTatCaBaiViet());
    }

    // Public: Xem chi tiết theo slug (VD: /api/bai-viet/cach-chon-giay)
    @GetMapping("/{slug}")
    public ResponseEntity<?> getDetail(@PathVariable String slug) {
        return ResponseEntity.ok(baiVietService.xemChiTiet(slug));
    }

    // Admin: Viết bài
    @PostMapping
    public ResponseEntity<?> create(@RequestBody BaiVietRequest request) {
        return ResponseEntity.ok(baiVietService.taoBaiViet(request.getTieuDe(), request.getTomTat(), request.getNoiDung()));
    }

    // Admin: Xóa bài
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        baiVietService.xoaBaiViet(id);
        return ResponseEntity.ok("Đã xóa bài viết");
    }
}