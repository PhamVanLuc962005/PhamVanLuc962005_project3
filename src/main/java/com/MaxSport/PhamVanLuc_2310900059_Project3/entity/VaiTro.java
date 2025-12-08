package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "vai_tro")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class VaiTro {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(unique = true, nullable = false)
    private String ten; // Ví dụ: ROLE_ADMIN, ROLE_USER

    private String moTa;
}
