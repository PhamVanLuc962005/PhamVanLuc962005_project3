package com.MaxSport.PhamVanLuc_2310900059_Project3.controller;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.ThuongHieu;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.ThuongHieuRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/thuong-hieu")
public class ThuongHieuController {
    @Autowired
    private ThuongHieuRepository thuongHieuRepository;

    @GetMapping
    public ResponseEntity<?> getAll() {
        return ResponseEntity.ok(thuongHieuRepository.findAll());
    }

    @PostMapping
    public ResponseEntity<?> create(@RequestBody ThuongHieu thuongHieu) {
        return ResponseEntity.ok(thuongHieuRepository.save(thuongHieu));
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> update(@PathVariable Integer id, @RequestBody ThuongHieu request) {
        ThuongHieu th = thuongHieuRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Thương hiệu không tồn tại"));
        th.setTen(request.getTen());
        th.setMoTa(request.getMoTa());
        return ResponseEntity.ok(thuongHieuRepository.save(th));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Integer id) {
        thuongHieuRepository.deleteById(id);
        return ResponseEntity.ok("Đã xóa thương hiệu");
    }
}