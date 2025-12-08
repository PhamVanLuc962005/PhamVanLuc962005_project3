package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "ton_kho", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"id_kho", "id_phien_ban"})
})
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class TonKho {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "id_kho", nullable = false)
    private KhoHang khoHang;

    @ManyToOne
    @JoinColumn(name = "id_phien_ban", nullable = false)
    private SanPhamPhienBan sanPhamPhienBan;

    private Integer soLuong;

    private Integer daGiu; // Hàng đang trong đơn đặt nhưng chưa xuất kho

    @Column(name = "ngay_cap_nhat")
    private LocalDateTime ngayCapNhat;
}