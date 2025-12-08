package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "canh_bao_ton_kho")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class CanhBaoTonKho {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @ManyToOne
    @JoinColumn(name = "id_san_pham")
    private SanPham sanPham;

    private Integer soLuongHienTai;
    private Integer nguongCanhBao;

    private String trangThai;

    private LocalDateTime thoiGianTao;
}