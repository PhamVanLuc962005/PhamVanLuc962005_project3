package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "tu_khoa_tim_kiem")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class TuKhoaTimKiem {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @ManyToOne
    @JoinColumn(name = "id_nguoi_dung")
    private NguoiDung nguoiDung;

    private String tuKhoa;
    private LocalDateTime thoiGianTim;
}
