package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "danh_gia_tuong_tac")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class DanhGiaTuongTac {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "id_danh_gia", nullable = false)
    private DanhGia danhGia;

    @ManyToOne
    @JoinColumn(name = "id_nguoi_dung", nullable = false)
    private NguoiDung nguoiDung;

    private String loai; // Like, Dislike
}