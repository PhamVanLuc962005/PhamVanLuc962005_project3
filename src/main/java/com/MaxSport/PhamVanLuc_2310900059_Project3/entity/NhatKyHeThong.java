package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "nhat_ky_he_thong")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class NhatKyHeThong {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String loaiThucThe;
    private Long idThucThe;
    private String hanhDong;
    private Long thucHienBoi;

    @Column(columnDefinition = "JSON")
    private String chiTiet;

    private LocalDateTime ngayTao;
}
