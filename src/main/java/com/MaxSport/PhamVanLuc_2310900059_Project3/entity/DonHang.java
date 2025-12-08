package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.math.BigDecimal;
import java.util.List;

@Entity
@Table(name = "don_hang")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class DonHang extends BaseEntity {

    @Column(name = "ma_don", unique = true)
    private String maDon;

    @ManyToOne
    @JoinColumn(name = "id_nguoi_dung")
    private NguoiDung nguoiDung;

    // Sử dụng String cho trạng thái hoặc Enum nếu muốn chặt chẽ hơn
    @Column(name = "trang_thai")
    private String trangThai; // DA_DAT, DANG_GIAO, HOAN_THANH

    @Column(name = "tong_tien")
    private BigDecimal tongTien;

    @Column(name = "phi_van_chuyen")
    private BigDecimal phiVanChuyen;

    @Column(name = "giam_gia")
    private BigDecimal giamGia;

    @Column(name = "phuong_thuc_thanh_toan")
    private String phuongThucThanhToan;

    @Column(name = "dia_chi_giao_hang", columnDefinition = "TEXT")
    private String diaChiGiaoHang;

    @OneToMany(mappedBy = "donHang", cascade = CascadeType.ALL)
    private List<DonHangChiTiet> chiTietDonHang;
}
