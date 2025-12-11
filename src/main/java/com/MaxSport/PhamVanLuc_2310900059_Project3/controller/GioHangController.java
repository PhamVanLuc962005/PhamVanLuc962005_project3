package com.MaxSport.PhamVanLuc_2310900059_Project3.controller;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.ThemGioHangRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.service.GioHangService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/gio-hang")
public class GioHangController {

    @Autowired
    private GioHangService gioHangService;

    // Xem giỏ hàng
    @GetMapping
    public ResponseEntity<?> getMyCart() {
        return ResponseEntity.ok(gioHangService.layGioHangCuaToi());
    }

    // Thêm vào giỏ
    @PostMapping("/them")
    public ResponseEntity<?> addToCart(@RequestBody ThemGioHangRequest request) {
        return ResponseEntity.ok(gioHangService.addToCart(request));
    }

    // Xóa khỏi giỏ
    @DeleteMapping("/xoa/{id}")
    public ResponseEntity<?> removeFromCart(@PathVariable Long id) {
        gioHangService.xoaKhoiGio(id);
        return ResponseEntity.ok("Đã xóa sản phẩm khỏi giỏ hàng");
    }
}