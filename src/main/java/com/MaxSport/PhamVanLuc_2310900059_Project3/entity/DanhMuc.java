package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.util.List;

@Entity
@Table(name = "danh_muc")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class DanhMuc extends BaseEntity {

    private String ten;

    @Column(name = "duong_dan", unique = true)
    private String duongDan;

    @Column(columnDefinition = "TEXT")
    private String moTa;

    // Quan hệ cha - con (Self-referencing)
    @ManyToOne
    @JoinColumn(name = "id_cha")
    private DanhMuc danhMucCha;

    @OneToMany(mappedBy = "danhMucCha")
    private List<DanhMuc> danhMucCon;
}