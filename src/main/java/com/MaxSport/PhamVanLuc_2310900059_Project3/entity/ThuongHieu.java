package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "thuong_hieu")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class ThuongHieu {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false)
    private String ten;

    @Column(unique = true)
    private String duongDan;

    @Column(columnDefinition = "TEXT")
    private String moTa;
}