package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "ma_giam_gia")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class MaGiamGia {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String ma;

    private String moTa;
    private String loai; // phan_tram, so_tien_co_dinh
    private BigDecimal giaTri;
    private BigDecimal donToiThieu;

    private Integer gioiHan;
    private Integer soLanDung;

    private LocalDateTime batDau;
    private LocalDateTime ketThuc;
    private Boolean kichHoat;
}