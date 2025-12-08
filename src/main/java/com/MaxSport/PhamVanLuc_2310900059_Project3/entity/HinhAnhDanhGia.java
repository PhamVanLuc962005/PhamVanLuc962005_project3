package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "hinh_anh_danh_gia")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class HinhAnhDanhGia {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "id_danh_gia", nullable = false)
    private DanhGia danhGia;

    private String duongDan;
}
