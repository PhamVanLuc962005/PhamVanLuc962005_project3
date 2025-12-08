package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "san_pham_hinh_anh")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class SanPhamHinhAnh {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "id_san_pham")
    private SanPham sanPham;

    @ManyToOne
    @JoinColumn(name = "id_phien_ban")
    private SanPhamPhienBan sanPhamPhienBan;

    @Column(nullable = false, length = 1000)
    private String duongDan;

    private Integer viTri;

    private Boolean hinhChinh;
}