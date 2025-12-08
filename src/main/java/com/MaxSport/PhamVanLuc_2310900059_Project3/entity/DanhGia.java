package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.util.List;

@Entity
@Table(name = "danh_gia")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class DanhGia extends BaseEntity {

    @ManyToOne
    @JoinColumn(name = "id_san_pham", nullable = false)
    private SanPham sanPham;

    @ManyToOne
    @JoinColumn(name = "id_nguoi_dung", nullable = false)
    private NguoiDung nguoiDung;

    private Integer diem; // 1-5
    private String tieuDe;

    @Column(columnDefinition = "TEXT")
    private String noiDung;

    private Boolean hinhAnhDinhKem;
    private Integer tongLike;
    private Integer tongDislike;
    private Boolean duyet;

    @OneToMany(mappedBy = "danhGia", cascade = CascadeType.ALL)
    private List<HinhAnhDanhGia> hinhAnhList;
}