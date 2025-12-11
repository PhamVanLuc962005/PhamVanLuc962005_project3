package com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class ThemGioHangRequest {

    @JsonProperty("idPhienBan")
    private Long idPhienBan;

    private Integer soLuong;
}