package com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request;

import lombok.Data;

@Data
public class DoiMatKhauRequest {
    private String matKhauCu;
    private String matKhauMoi;
    private String xacNhanMatKhau; // (Optional) Frontend có thể check, nhưng Backend cũng nên biết
}