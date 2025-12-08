package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "thong_bao")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class ThongBao {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "id_nguoi_dung")
    private NguoiDung nguoiDung;

    private String loai;
    private String kenh; // Email, SMS...
    private String tieuDe;

    @Column(columnDefinition = "TEXT")
    private String noiDung;

    private LocalDateTime thoiGianGui;
    private String trangThai;
}
