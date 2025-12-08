package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "banner")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class Banner {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String tieuDe;
    private String hinhAnh;
    private String lienKet;
    private Integer uuTien;
    private Boolean kichHoat;
}