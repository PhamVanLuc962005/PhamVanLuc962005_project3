package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "kho_hang")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class KhoHang extends BaseEntity { // Có ngay_tao
    private String ten;

    @Column(columnDefinition = "TEXT")
    private String diaChi;

    private String soDienThoai;
}