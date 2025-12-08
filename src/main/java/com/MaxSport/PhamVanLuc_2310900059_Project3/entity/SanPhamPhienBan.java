package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import jakarta.persistence.*;
import lombok.*;
import java.math.BigDecimal;
import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "san_pham_phien_ban")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class SanPhamPhienBan extends BaseEntity {

    @ManyToOne
    @JoinColumn(name = "id_san_pham", nullable = false)
    @JsonIgnore
    private SanPham sanPham;

    @Column(name = "ma_sku_phien_ban", unique = true)
    private String maSkuPhienBan;

    @Column(columnDefinition = "JSON")
    private String thuocTinh;

    @Column(name = "gia_ban")
    private BigDecimal giaBan;

    private BigDecimal khoiLuong;
}