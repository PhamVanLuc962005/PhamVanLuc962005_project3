package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "van_don")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class VanDon {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "id_don_hang", nullable = false)
    private DonHang donHang;

    @ManyToOne
    @JoinColumn(name = "id_kho")
    private KhoHang khoHang;

    private String donViVanChuyen;
    private String maVanDon;
    private String trangThai;

    private LocalDateTime thoiGianGui;
    private LocalDateTime thoiGianGiao;
}