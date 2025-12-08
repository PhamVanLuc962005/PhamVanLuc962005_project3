package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "van_don_chi_tiet")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class VanDonChiTiet {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "id_van_don", nullable = false)
    private VanDon vanDon;

    @ManyToOne
    @JoinColumn(name = "id_chi_tiet_don", nullable = false)
    private DonHangChiTiet donHangChiTiet;

    private Integer soLuong;
}
