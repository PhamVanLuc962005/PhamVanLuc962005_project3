package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import com.fasterxml.jackson.annotation.JsonIgnore;
import java.time.LocalDateTime;

@Entity
@Table(name = "phan_hoi_khieu_nai")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class PhanHoiKhieuNai {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "id_khieu_nai", nullable = false)
    @JsonIgnore
    private KhieuNai khieuNai;

    @ManyToOne
    @JoinColumn(name = "id_nguoi_dung", nullable = false)
    private NguoiDung nguoiDung; // Người trả lời (Admin hoặc User)

    @Column(columnDefinition = "TEXT")
    private String noiDung;

    private LocalDateTime thoiGian;
}