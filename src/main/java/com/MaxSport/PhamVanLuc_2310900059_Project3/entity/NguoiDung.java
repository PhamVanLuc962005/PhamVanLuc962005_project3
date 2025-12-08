package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.util.Set;

@Entity
@Table(name = "nguoi_dung")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class NguoiDung extends BaseEntity {

    @Column(name = "ten_dang_nhap", length = 100)
    private String tenDangNhap;

    @Column(unique = true, length = 255)
    private String email;

    @Column(name = "so_dien_thoai", unique = true, length = 20)
    private String soDienThoai;

    @Column(name = "mat_khau_hash", nullable = false)
    private String matKhauHash;

    @Column(name = "ho_ten")
    private String hoTen;

    @Column(name = "dia_chi", columnDefinition = "TEXT")
    private String diaChi;

    @Column(columnDefinition = "BOOLEAN DEFAULT TRUE")
    private Boolean kichHoat;

    // Quan hệ Many-to-Many với VaiTro
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "nguoi_dung_vai_tro",
            joinColumns = @JoinColumn(name = "id_nguoi_dung"),
            inverseJoinColumns = @JoinColumn(name = "id_vai_tro")
    )
    private Set<VaiTro> vaiTro;
}