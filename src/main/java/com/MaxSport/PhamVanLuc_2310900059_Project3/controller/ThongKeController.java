package com.MaxSport.PhamVanLuc_2310900059_Project3.controller;

import com.MaxSport.PhamVanLuc_2310900059_Project3.service.ThongKeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/thong-ke")
public class ThongKeController {

    @Autowired
    private ThongKeService thongKeService;

    // Chỉ Admin mới được xem thống kê
    @GetMapping("/tong-quat")
    public ResponseEntity<?> getGeneralStats() {
        return ResponseEntity.ok(thongKeService.layThongKeTongQuat());
    }
}