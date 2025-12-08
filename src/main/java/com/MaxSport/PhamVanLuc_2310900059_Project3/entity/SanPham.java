package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.math.BigDecimal;
import java.util.List;

@Entity
@Table(name = "san_pham")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class SanPham extends BaseEntity {

    @Column(nullable = false)
    private String ten;

    @Column(name = "ma_sku", unique = true)
    private String maSku;

    @Column(name = "hinh_anh")
    private String hinhAnh;

    @Column(name = "mo_ta_ngan", columnDefinition = "TEXT")
    private String moTaNgan;

    @Column(name = "mo_ta_chi_tiet", columnDefinition = "LONGTEXT")
    private String moTaChiTiet;

    @Column(name = "gia_goc")
    private BigDecimal giaGoc;

    private Boolean hienThi;

    @ManyToOne
    @JoinColumn(name = "id_thuong_hieu")
    private ThuongHieu thuongHieu;

    @ManyToOne
    @JoinColumn(name = "id_danh_muc")
    private DanhMuc danhMuc;

    // Một sản phẩm có nhiều phiên bản (Màu/Size)
    @OneToMany(mappedBy = "sanPham", cascade = CascadeType.ALL)
    private List<SanPhamPhienBan> phienBan;
}