package com.MaxSport.PhamVanLuc_2310900059_Project3.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "gio_hang")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class GioHang extends BaseEntity {

    @OneToOne
    @JoinColumn(name = "id_nguoi_dung")
    @JsonIgnore
    private NguoiDung nguoiDung;

    @OneToMany(mappedBy = "gioHang", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<GioHangSanPham> chiTietGioHang = new ArrayList<>();
}