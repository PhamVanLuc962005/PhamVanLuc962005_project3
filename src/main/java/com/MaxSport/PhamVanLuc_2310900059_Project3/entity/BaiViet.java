package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "bai_viet")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class BaiViet extends BaseEntity {

    private String tieuDe;

    @Column(unique = true)
    private String duongDan;

    @Column(columnDefinition = "TEXT")
    private String tomTat;

    @Column(columnDefinition = "LONGTEXT")
    private String noiDung;

    @ManyToOne
    @JoinColumn(name = "id_tac_gia")
    private NguoiDung tacGia;

    private LocalDateTime thoiGianDang;
}
