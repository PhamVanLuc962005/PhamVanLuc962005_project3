package com.MaxSport.PhamVanLuc_2310900059_Project3.dto.response;

import lombok.Data;
import java.time.LocalDateTime;

@Data
public class DanhGiaResponse {
    private String tenNguoiDung; // Chỉ hiện tên, không hiện ID/Email
    private Integer diem;
    private String tieuDe;
    private String noiDung;
    private LocalDateTime ngayTao;
}