package com.MaxSport.PhamVanLuc_2310900059_Project3.controller;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.DanhGiaRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.service.DanhGiaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/danh-gia")
public class DanhGiaController {

    @Autowired
    private DanhGiaService danhGiaService;

    // API Viết đánh giá (Cần Login)
    @PostMapping
    public ResponseEntity<?> addReview(@RequestBody DanhGiaRequest request) {
        return ResponseEntity.ok(danhGiaService.themDanhGia(request));
    }

    // API Xem đánh giá theo Sản phẩm (Public)
    @GetMapping("/san-pham/{id}")
    public ResponseEntity<?> getReviewsByProduct(@PathVariable Long id) {
        return ResponseEntity.ok(danhGiaService.layDanhGiaCuaSanPham(id));
    }
}