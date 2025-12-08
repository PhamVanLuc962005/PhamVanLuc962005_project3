package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "khieu_nai")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class KhieuNai {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "id_nguoi_dung")
    private NguoiDung nguoiDung;

    @ManyToOne
    @JoinColumn(name = "id_don_hang")
    private DonHang donHang;

    @Column(columnDefinition = "TEXT")
    private String noiDung;

    private String hinhAnhDinhKem;
    private String trangThai; // Tiep nhan, Dang xu ly...

    private LocalDateTime ngayTao;
    private LocalDateTime ngayCapNhat;
}
