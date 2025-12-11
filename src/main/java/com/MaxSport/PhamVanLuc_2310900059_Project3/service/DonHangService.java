package com.MaxSport.PhamVanLuc_2310900059_Project3.service;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.ChiTietDatHangRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.DatHangRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.*;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class DonHangService {

    @Autowired private DonHangRepository donHangRepository;
    @Autowired private DonHangChiTietRepository chiTietRepository;
    @Autowired private SanPhamPhienBanRepository phienBanRepository;
    @Autowired private NguoiDungRepository nguoiDungRepository;
    @Autowired private TonKhoRepository tonKhoRepository;
    @Autowired private EmailService emailService;
    @Autowired private MaGiamGiaRepository maGiamGiaRepository;
    @Autowired private GioHangRepository gioHangRepository;
    @Autowired private GioHangSanPhamRepository gioHangSanPhamRepository;

    // --- 1. CHỨC NĂNG ĐẶT HÀNG (Full Flow) ---
    @Transactional
    public DonHang taoDonHang(DatHangRequest request) {
        // 1. Lấy User
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        NguoiDung user = nguoiDungRepository.findByEmail(username)
                .orElseThrow(() -> new RuntimeException("Người dùng không tồn tại"));

        // 2. Khởi tạo đơn (Lưu nháp để lấy ID)
        DonHang donHang = new DonHang();
        donHang.setMaDon("ORD-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase());
        donHang.setNguoiDung(user);
        donHang.setDiaChiGiaoHang(request.getDiaChiGiaoHang());
        donHang.setPhuongThucThanhToan(request.getPhuongThucThanhToan());
        donHang.setTrangThai("CHO_XU_LY");
        donHang = donHangRepository.save(donHang);

        // 3. Xử lý sản phẩm & Tính tiền
        BigDecimal tongTienGoc = BigDecimal.ZERO;
        List<DonHangChiTiet> listChiTiet = new ArrayList<>();

        for (ChiTietDatHangRequest item : request.getDanhSachSanPham()) {
            SanPhamPhienBan phienBan = phienBanRepository.findById(item.getIdPhienBan())
                    .orElseThrow(() -> new RuntimeException("Sản phẩm ID " + item.getIdPhienBan() + " không tồn tại"));

            // Check kho & Trừ kho
            TonKho tonKho = tonKhoRepository.findByKhoHangIdAndSanPhamPhienBanId(1, item.getIdPhienBan())
                    .orElseThrow(() -> new RuntimeException("Sản phẩm chưa nhập kho!"));

            if (tonKho.getSoLuong() < item.getSoLuong()) {
                throw new RuntimeException("Kho chỉ còn " + tonKho.getSoLuong() + " sản phẩm: " + phienBan.getSanPham().getTen());
            }
            tonKho.setSoLuong(tonKho.getSoLuong() - item.getSoLuong());
            tonKhoRepository.save(tonKho);

            // Tính tiền
            BigDecimal thanhTien = phienBan.getGiaBan().multiply(BigDecimal.valueOf(item.getSoLuong()));
            tongTienGoc = tongTienGoc.add(thanhTien);

            // Tạo chi tiết
            DonHangChiTiet chiTiet = new DonHangChiTiet();
            chiTiet.setDonHang(donHang);
            chiTiet.setSanPhamPhienBan(phienBan);
            chiTiet.setTenSanPham(phienBan.getSanPham().getTen());
            chiTiet.setSoLuong(item.getSoLuong());
            chiTiet.setGia(phienBan.getGiaBan());
            chiTiet.setThanhTien(thanhTien);
            listChiTiet.add(chiTiet);
        }

        // Lưu danh sách chi tiết
        chiTietRepository.saveAll(listChiTiet);

        // 4. Xử lý Mã giảm giá (Voucher)
        BigDecimal soTienGiam = BigDecimal.ZERO;
        if (request.getMaGiamGia() != null && !request.getMaGiamGia().isEmpty()) {
            MaGiamGia voucher = maGiamGiaRepository.findByMa(request.getMaGiamGia())
                    .orElseThrow(() -> new RuntimeException("Mã giảm giá không tồn tại!"));

            if (voucher.getKetThuc().isBefore(LocalDateTime.now())) throw new RuntimeException("Mã hết hạn!");
            if (voucher.getGioiHan() != null && voucher.getSoLanDung() >= voucher.getGioiHan()) throw new RuntimeException("Mã hết lượt!");
            if (tongTienGoc.compareTo(voucher.getDonToiThieu()) < 0) throw new RuntimeException("Chưa đạt giá trị tối thiểu!");

            if ("tien_mat".equals(voucher.getLoai())) {
                soTienGiam = voucher.getGiaTri();
            } else if ("phan_tram".equals(voucher.getLoai())) {
                soTienGiam = tongTienGoc.multiply(voucher.getGiaTri()).divide(BigDecimal.valueOf(100));
            }

            // Tăng số lần dùng
            voucher.setSoLanDung(voucher.getSoLanDung() + 1);
            maGiamGiaRepository.save(voucher);
        }

        // 5. Chốt đơn & Xóa giỏ hàng
        BigDecimal tongTienCuoiCung = tongTienGoc.subtract(soTienGiam).max(BigDecimal.ZERO);

        donHang.setGiamGia(soTienGiam);
        donHang.setTongTien(tongTienCuoiCung);

        // Cập nhật lại đơn hàng lần cuối
        DonHang donHangHoanThanh = donHangRepository.save(donHang);

        // Xóa giỏ hàng
        GioHang gioHang = gioHangRepository.findByNguoiDungId(user.getId()).orElse(null);
        if (gioHang != null) {
            gioHangSanPhamRepository.deleteByGioHang(gioHang);
        }

        // 6. Gửi Email
        try {
            emailService.guiEmailXacNhanDonHang(user.getEmail(), donHangHoanThanh);
        } catch (Exception e) {
            System.err.println("Lỗi gửi mail: " + e.getMessage());
        }

        return donHangHoanThanh;
    }

    // --- 2. LỊCH SỬ ĐƠN HÀNG (User) ---
    public List<DonHang> layLichSuDonHang() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        NguoiDung user = nguoiDungRepository.findByEmail(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return donHangRepository.findByNguoiDungId(user.getId());
    }

    // --- 3. QUẢN LÝ ĐƠN HÀNG (Admin) ---
    public List<DonHang> layTatCaDonHang() {
        return donHangRepository.findAll();
    }

    public DonHang capNhatTrangThai(Long idDonHang, String trangThaiMoi) {
        DonHang donHang = donHangRepository.findById(idDonHang)
                .orElseThrow(() -> new RuntimeException("Đơn hàng không tồn tại"));
        donHang.setTrangThai(trangThaiMoi);
        return donHangRepository.save(donHang);
    }
}