package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;
import java.math.BigDecimal;

@Entity
@Table(name = "don_hang_chi_tiet")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class DonHangChiTiet {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "id_don_hang")
    @JsonIgnore
    private DonHang donHang;

    @ManyToOne
    @JoinColumn(name = "id_phien_ban")
    private SanPhamPhienBan sanPhamPhienBan;

    @Column(name = "ten_san_pham")
    private String tenSanPham;

    private Integer soLuong;

    private BigDecimal gia;

    private BigDecimal thanhTien;
}
