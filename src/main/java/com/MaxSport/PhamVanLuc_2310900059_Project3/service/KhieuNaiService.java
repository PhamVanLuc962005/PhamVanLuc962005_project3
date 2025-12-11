package com.MaxSport.PhamVanLuc_2310900059_Project3.service;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.PhanHoiRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.DonHang;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.KhieuNai;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.NguoiDung;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.PhanHoiKhieuNai;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.DonHangRepository;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.KhieuNaiRepository;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.NguoiDungRepository;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.PhanHoiKhieuNaiRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class KhieuNaiService {

    @Autowired
    private KhieuNaiRepository khieuNaiRepository;

    @Autowired
    private PhanHoiKhieuNaiRepository phanHoiRepository;

    @Autowired
    private DonHangRepository donHangRepository;

    @Autowired
    private NguoiDungRepository nguoiDungRepository;

    @Autowired
    private FileStorageService fileStorageService;

    // 1. Tạo khiếu nại mới (User)
    public KhieuNai taoKhieuNai(Long idDonHang, String noiDung, MultipartFile file) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        NguoiDung user = nguoiDungRepository.findByEmail(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        DonHang donHang = donHangRepository.findById(idDonHang)
                .orElseThrow(() -> new RuntimeException("Đơn hàng không tồn tại"));

        // Kiểm tra xem đơn hàng này có đúng là của user đó không
        if (!donHang.getNguoiDung().getId().equals(user.getId())) {
            throw new RuntimeException("Bạn không có quyền khiếu nại đơn hàng này");
        }

        KhieuNai khieuNai = new KhieuNai();
        khieuNai.setNguoiDung(user);
        khieuNai.setDonHang(donHang);
        khieuNai.setNoiDung(noiDung);
        khieuNai.setTrangThai("Tiep nhan"); // Trạng thái mặc định
        khieuNai.setNgayTao(LocalDateTime.now());
        khieuNai.setNgayCapNhat(LocalDateTime.now());

        // Upload ảnh nếu có
        if (file != null && !file.isEmpty()) {
            String fileName = fileStorageService.luuFile(file);
            khieuNai.setHinhAnhDinhKem(fileName);
        }

        return khieuNaiRepository.save(khieuNai);
    }

    // 2. Lấy danh sách khiếu nại của User
    public List<KhieuNai> layKhieuNaiCuaToi() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        NguoiDung user = nguoiDungRepository.findByEmail(username).get();
        return khieuNaiRepository.findByNguoiDungId(user.getId());
    }

    // 3. Lấy tất cả khiếu nại (Admin)
    public List<KhieuNai> layTatCaKhieuNai() {
        return khieuNaiRepository.findAll();
    }

    // 4. Admin cập nhật trạng thái (Duyệt/Từ chối)
    public KhieuNai capNhatTrangThai(Long id, String trangThai) {
        KhieuNai kn = khieuNaiRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Khiếu nại không tồn tại"));
        kn.setTrangThai(trangThai);
        kn.setNgayCapNhat(LocalDateTime.now());
        return khieuNaiRepository.save(kn);
    }

    // 5. Gửi phản hồi (Chat qua lại giữa Admin và User)
    public PhanHoiKhieuNai guiPhanHoi(Long idKhieuNai, PhanHoiRequest request) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        NguoiDung user = nguoiDungRepository.findByEmail(username).get();

        KhieuNai kn = khieuNaiRepository.findById(idKhieuNai)
                .orElseThrow(() -> new RuntimeException("Khiếu nại không tồn tại"));

        PhanHoiKhieuNai phanHoi = new PhanHoiKhieuNai();
        phanHoi.setKhieuNai(kn);
        phanHoi.setNguoiDung(user); // Người trả lời (có thể là Admin hoặc User)
        phanHoi.setNoiDung(request.getNoiDung());
        phanHoi.setThoiGian(LocalDateTime.now());

        return phanHoiRepository.save(phanHoi);
    }

    // 6. Xem chi tiết hội thoại của 1 khiếu nại
    public List<PhanHoiKhieuNai> layHoiThoai(Long idKhieuNai) {
        return phanHoiRepository.findByKhieuNaiIdOrderByThoiGianAsc(idKhieuNai);
    }
}