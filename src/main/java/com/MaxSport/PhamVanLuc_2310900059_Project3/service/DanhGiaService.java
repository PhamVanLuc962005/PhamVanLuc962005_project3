package com.MaxSport.PhamVanLuc_2310900059_Project3.service;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.DanhGiaRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.response.DanhGiaResponse;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.DanhGia;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.NguoiDung;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.SanPham;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.DanhGiaRepository;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.NguoiDungRepository;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.SanPhamRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class DanhGiaService {

    @Autowired
    private DanhGiaRepository danhGiaRepository;

    @Autowired
    private NguoiDungRepository nguoiDungRepository;

    @Autowired
    private SanPhamRepository sanPhamRepository;

    // 1. Thêm đánh giá mới
    public DanhGia themDanhGia(DanhGiaRequest request) {
        // Lấy User hiện tại
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        NguoiDung user = nguoiDungRepository.findByEmail(username)
                .orElseThrow(() -> new RuntimeException("Người dùng không tồn tại"));

        // Lấy Sản phẩm
        SanPham sanPham = sanPhamRepository.findById(request.getIdSanPham())
                .orElseThrow(() -> new RuntimeException("Sản phẩm không tồn tại"));

        // Tạo Entity
        DanhGia danhGia = new DanhGia();
        danhGia.setNguoiDung(user);
        danhGia.setSanPham(sanPham);
        danhGia.setDiem(request.getDiem());
        danhGia.setTieuDe(request.getTieuDe());
        danhGia.setNoiDung(request.getNoiDung());
        danhGia.setDuyet(true); // Tạm thời cho hiện luôn không cần duyệt

        return danhGiaRepository.save(danhGia);
    }

    // 2. Lấy danh sách đánh giá của 1 sản phẩm
    public List<DanhGiaResponse> layDanhGiaCuaSanPham(Long idSanPham) {
        List<DanhGia> list = danhGiaRepository.findBySanPhamId(idSanPham);

        // Chuyển đổi sang DTO để trả về cho Frontend
        return list.stream().map(dg -> {
            DanhGiaResponse dto = new DanhGiaResponse();
            dto.setTenNguoiDung(dg.getNguoiDung().getHoTen()); // Lấy tên thật của người dùng
            dto.setDiem(dg.getDiem());
            dto.setTieuDe(dg.getTieuDe());
            dto.setNoiDung(dg.getNoiDung());
            dto.setNgayTao(dg.getNgayTao());
            return dto;
        }).collect(Collectors.toList());
    }
}