package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "bo_loc_san_pham")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class BoLocSanPham {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @ManyToOne
    @JoinColumn(name = "id_nguoi_dung")
    private NguoiDung nguoiDung;

    private Integer danhMuc;
    private String thuongHieu;
    private BigDecimal giaTu;
    private BigDecimal giaDen;
    private String mauSac;
    private String kichThuoc;
    private String sapXep;
    private LocalDateTime ngayTao;
}
