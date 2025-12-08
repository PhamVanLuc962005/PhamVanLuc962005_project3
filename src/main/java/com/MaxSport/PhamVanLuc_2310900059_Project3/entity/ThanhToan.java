package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "thanh_toan")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class ThanhToan extends BaseEntity {

    @ManyToOne
    @JoinColumn(name = "id_don_hang", nullable = false)
    private DonHang donHang;

    private String kenh; // VNPAY, MOMO...

    @Column(name = "ma_giao_dich") // CẦN THÊM name = "ma_giao_dich"
    private String maGiaoDich;

    private BigDecimal soTien;
    private String trangThai;
    private LocalDateTime thoiGianThanhToan;
}