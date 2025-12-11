package com.MaxSport.PhamVanLuc_2310900059_Project3.controller;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.NhapKhoRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.service.KhoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/kho")
public class KhoController {

    @Autowired
    private KhoService khoService;

    // API Nhập kho (Chỉ Admin)
    @PostMapping("/nhap")
    public ResponseEntity<?> importStock(@RequestBody NhapKhoRequest request) {
        return ResponseEntity.ok(khoService.nhapKho(request));
    }
    // GET /api/kho/xem-ton-kho?idPhienBan=1
    @GetMapping("/xem-ton-kho")
    public ResponseEntity<?> checkStock(@RequestParam Long idPhienBan) {
        Integer soLuong = khoService.xemSoLuongTon(idPhienBan);
        return ResponseEntity.ok(soLuong); // Trả về con số (VD: 10)
    }
}