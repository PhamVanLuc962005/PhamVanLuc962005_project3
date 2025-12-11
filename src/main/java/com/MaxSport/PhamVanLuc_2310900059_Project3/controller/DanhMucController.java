package com.MaxSport.PhamVanLuc_2310900059_Project3.controller;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.DanhMuc;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.DanhMucRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/danh-muc")
public class DanhMucController {
    @Autowired
    private DanhMucRepository danhMucRepository;

    // 1. Lấy danh sách (Đã có)
    @GetMapping
    public ResponseEntity<?> getAll() {
        return ResponseEntity.ok(danhMucRepository.findAll());
    }

    // 2. Thêm mới
    @PostMapping
    public ResponseEntity<?> create(@RequestBody DanhMuc danhMuc) {
        return ResponseEntity.ok(danhMucRepository.save(danhMuc));
    }

    // 3. Cập nhật
    @PutMapping("/{id}")
    public ResponseEntity<?> update(@PathVariable Integer id, @RequestBody DanhMuc request) {
        DanhMuc dm = danhMucRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Danh mục không tồn tại"));
        dm.setTen(request.getTen());
        dm.setMoTa(request.getMoTa());
        // Cập nhật đường dẫn nếu cần (hoặc giữ nguyên)
        return ResponseEntity.ok(danhMucRepository.save(dm));
    }

    // 4. Xóa
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Integer id) {
        danhMucRepository.deleteById(id);
        return ResponseEntity.ok("Đã xóa danh mục");
    }
}