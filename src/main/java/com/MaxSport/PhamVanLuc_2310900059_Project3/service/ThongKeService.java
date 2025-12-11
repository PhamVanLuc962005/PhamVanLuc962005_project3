package com.MaxSport.PhamVanLuc_2310900059_Project3.service;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.response.ThongKeResponse;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.DonHangRepository;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.NguoiDungRepository;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.SanPhamRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;

@Service
public class ThongKeService {

    @Autowired
    private DonHangRepository donHangRepository;

    @Autowired
    private NguoiDungRepository nguoiDungRepository;

    @Autowired
    private SanPhamRepository sanPhamRepository;

    public ThongKeResponse layThongKeTongQuat() {
        // 1. Tính toán các số liệu
        BigDecimal doanhThu = donHangRepository.tinhTongDoanhThu();
        Long tongDon = donHangRepository.count();
        Long donChoXuLy = donHangRepository.countByTrangThai("CHO_XU_LY");
        Long donDangGiao = donHangRepository.countByTrangThai("DANG_GIAO");
        Long donHoanThanh = donHangRepository.countByTrangThai("HOAN_THANH");

        Long soUser = nguoiDungRepository.count();
        Long soSanPham = sanPhamRepository.count();

        // 2. Đóng gói vào DTO
        return ThongKeResponse.builder()
                .tongDoanhThu(doanhThu)
                .tongSoDonHang(tongDon)
                .soDonChoXuLy(donChoXuLy)
                .soDonDangGiao(donDangGiao)
                .soDonHoanThanh(donHoanThanh)
                .tongSoNguoiDung(soUser)
                .tongSoSanPham(soSanPham)
                .build();
    }
}