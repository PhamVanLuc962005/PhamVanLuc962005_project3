package com.MaxSport.PhamVanLuc_2310900059_Project3.service;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.ThemGioHangRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.*;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Optional;

@Service
public class GioHangService {

    @Autowired
    private GioHangRepository gioHangRepository;

    @Autowired
    private GioHangSanPhamRepository gioHangSanPhamRepository;

    @Autowired
    private NguoiDungRepository nguoiDungRepository;

    @Autowired
    private SanPhamPhienBanRepository phienBanRepository;

    // 1. Lấy giỏ hàng hiện tại của User (Nếu chưa có thì tạo mới)
    public GioHang layGioHangCuaToi() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        NguoiDung user = nguoiDungRepository.findByEmail(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return gioHangRepository.findByNguoiDungId(user.getId())
                .orElseGet(() -> {
                    GioHang newCart = new GioHang();
                    newCart.setNguoiDung(user);
                    return gioHangRepository.save(newCart);
                });
    }

    // 2. Thêm sản phẩm vào giỏ
    @Transactional
    public GioHang addToCart(ThemGioHangRequest request) {
        GioHang gioHang = layGioHangCuaToi();

        if (gioHang.getChiTietGioHang() == null) {
            gioHang.setChiTietGioHang(new ArrayList<>());
        }

        SanPhamPhienBan phienBan = phienBanRepository.findById(request.getIdPhienBan())
                .orElseThrow(() -> new RuntimeException("Sản phẩm không tồn tại"));

        // Kiểm tra xem sản phẩm này đã có trong giỏ chưa
        Optional<GioHangSanPham> existingItem = gioHang.getChiTietGioHang().stream()
                .filter(item -> item.getSanPhamPhienBan().getId().equals(request.getIdPhienBan()))
                .findFirst();

        if (existingItem.isPresent()) {
            // Nếu có rồi -> Cộng thêm số lượng
            GioHangSanPham item = existingItem.get();
            item.setSoLuong(item.getSoLuong() + request.getSoLuong());
            gioHangSanPhamRepository.save(item);
        } else {
            // Nếu chưa có -> Tạo mới
            GioHangSanPham newItem = new GioHangSanPham();
            newItem.setGioHang(gioHang);
            newItem.setSanPhamPhienBan(phienBan);
            newItem.setSoLuong(request.getSoLuong());
            newItem.setNgayThem(LocalDateTime.now());
            gioHangSanPhamRepository.save(newItem);
        }

        // Refresh lại giỏ hàng từ DB để trả về dữ liệu mới nhất
        return gioHangRepository.findById(gioHang.getId()).get();
    }

    // 3. Xóa một sản phẩm khỏi giỏ
    public void xoaKhoiGio(Long idChiTietGioHang) {
        gioHangSanPhamRepository.deleteById(idChiTietGioHang);
    }
}