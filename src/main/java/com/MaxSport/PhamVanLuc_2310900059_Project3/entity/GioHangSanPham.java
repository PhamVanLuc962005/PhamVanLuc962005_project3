package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "gio_hang_san_pham")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class GioHangSanPham {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "id_gio_hang", nullable = false)
    @JsonIgnore
    private GioHang gioHang;

    @ManyToOne
    @JoinColumn(name = "id_phien_ban", nullable = false)
    private SanPhamPhienBan sanPhamPhienBan;

    private Integer soLuong;

    private LocalDateTime ngayThem;
}