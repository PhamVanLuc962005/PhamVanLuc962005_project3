package com.MaxSport.PhamVanLuc_2310900059_Project3.controller;

import com.MaxSport.PhamVanLuc_2310900059_Project3.service.BannerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/banner")
public class BannerController {

    @Autowired
    private BannerService bannerService;

    // API Public: Lấy danh sách banner để hiện lên Slider trang chủ
    @GetMapping("/hien-thi")
    public ResponseEntity<?> getPublicBanners() {
        return ResponseEntity.ok(bannerService.layBannerTrangChu());
    }

    // API Admin: Xem tất cả
    @GetMapping("/quan-ly")
    public ResponseEntity<?> getAllBanners() {
        return ResponseEntity.ok(bannerService.layTatCaBanner());
    }

    // API Admin: Thêm Banner mới (Dùng form-data)
    @PostMapping
    public ResponseEntity<?> createBanner(
            @RequestParam("tieuDe") String tieuDe,
            @RequestParam(value = "lienKet", required = false) String lienKet, // Link khi bấm vào ảnh
            @RequestParam(value = "uuTien", defaultValue = "0") Integer uuTien,
            @RequestParam("file") MultipartFile file) {

        return ResponseEntity.ok(bannerService.themBanner(tieuDe, lienKet, uuTien, file));
    }

    // API Admin: Xóa Banner
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteBanner(@PathVariable Integer id) {
        bannerService.xoaBanner(id);
        return ResponseEntity.ok("Đã xóa banner");
    }

    // API Admin: Bật/Tắt Banner
    @PutMapping("/{id}/toggle")
    public ResponseEntity<?> toggleBanner(@PathVariable Integer id) {
        return ResponseEntity.ok(bannerService.toggleBanner(id));
    }
}