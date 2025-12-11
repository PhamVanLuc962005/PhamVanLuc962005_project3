package com.MaxSport.PhamVanLuc_2310900059_Project3.service;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.PhienBanRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.SanPhamRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.response.PhienBanResponse;
import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.response.SanPhamChiTietResponse;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.*;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class SanPhamService {

    @Autowired
    private SanPhamRepository sanPhamRepository;

    @Autowired
    private ThuongHieuRepository thuongHieuRepository;

    @Autowired
    private DanhMucRepository danhMucRepository;

    @Autowired
    private SanPhamPhienBanRepository phienBanRepository;

    @Autowired
    private SanPhamHinhAnhRepository hinhAnhRepository;

    @Autowired
    private FileStorageService fileStorageService;

    // 1. Lấy danh sách sản phẩm (Admin dùng)
    public List<SanPham> layTatCaSanPham() {
        return sanPhamRepository.findAll();
    }

    // 2. Thêm sản phẩm mới
    public SanPham themSanPham(SanPhamRequest request) {
        ThuongHieu thuongHieu = thuongHieuRepository.findById(request.getIdThuongHieu())
                .orElseThrow(() -> new RuntimeException("Thương hiệu không tồn tại"));

        DanhMuc danhMuc = danhMucRepository.findById(request.getIdDanhMuc())
                .orElseThrow(() -> new RuntimeException("Danh mục không tồn tại"));

        SanPham sanPham = SanPham.builder()
                .ten(request.getTen())
                .maSku(request.getMaSku())
                .moTaNgan(request.getMoTaNgan())
                .moTaChiTiet(request.getMoTaChiTiet())
                .giaGoc(request.getGiaGoc())
                .hienThi(request.getHienThi() != null ? request.getHienThi() : true)
                .thuongHieu(thuongHieu)
                .danhMuc(danhMuc)
                .build();

        return sanPhamRepository.save(sanPham);
    }

    // 3. Thêm Phiên bản
    public SanPhamPhienBan themPhienBan(Long sanPhamId, PhienBanRequest request) {
        SanPham sanPham = sanPhamRepository.findById(sanPhamId)
                .orElseThrow(() -> new RuntimeException("Sản phẩm không tồn tại"));

        SanPhamPhienBan phienBan = new SanPhamPhienBan();
        phienBan.setSanPham(sanPham);
        phienBan.setMaSkuPhienBan(request.getMaSkuPhienBan());
        phienBan.setGiaBan(request.getGiaBan());
        phienBan.setKhoiLuong(request.getKhoiLuong());
        phienBan.setThuocTinh(request.getThuocTinh());

        return phienBanRepository.save(phienBan);
    }

    // 4. Lấy chi tiết sản phẩm
    public SanPhamChiTietResponse layChiTietSanPham(Long id) {
        SanPham sp = sanPhamRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Sản phẩm không tìm thấy!"));

        SanPhamChiTietResponse response = new SanPhamChiTietResponse();
        response.setId(sp.getId());
        response.setTen(sp.getTen());
        response.setMaSku(sp.getMaSku());
        response.setMoTaChiTiet(sp.getMoTaChiTiet());
        response.setGiaGoc(sp.getGiaGoc());
        response.setHinhAnh(sp.getHinhAnh());

        if (sp.getThuongHieu() != null) response.setTenThuongHieu(sp.getThuongHieu().getTen());
        if (sp.getDanhMuc() != null) response.setTenDanhMuc(sp.getDanhMuc().getTen());

        List<PhienBanResponse> listPhienBan = sp.getPhienBan().stream().map(pb -> {
            PhienBanResponse pbDto = new PhienBanResponse();
            pbDto.setId(pb.getId());
            pbDto.setMaSku(pb.getMaSkuPhienBan());
            pbDto.setGiaBan(pb.getGiaBan());
            pbDto.setThuocTinh(pb.getThuocTinh());
            return pbDto;
        }).collect(Collectors.toList());

        response.setDanhSachPhienBan(listPhienBan);
        return response;
    }

    // 5. Upload Ảnh (Đã sửa logic để hiện ảnh ngoài danh sách)
    public SanPhamHinhAnh themHinhAnh(Long sanPhamId, MultipartFile file) {
        SanPham sp = sanPhamRepository.findById(sanPhamId)
                .orElseThrow(() -> new RuntimeException("Sản phẩm không tồn tại"));

        // Lưu file vào ổ cứng và lấy tên UUID
        String fileName = fileStorageService.luuFile(file);

        // a. Lưu vào bảng SanPhamHinhAnh (Chi tiết)
        SanPhamHinhAnh hinhAnh = new SanPhamHinhAnh();
        hinhAnh.setSanPham(sp);
        hinhAnh.setDuongDan(fileName);
        hinhAnh.setHinhChinh(true);
        SanPhamHinhAnh savedImage = hinhAnhRepository.save(hinhAnh);


        // b. Cập nhật ảnh đại diện cho Sản phẩm cha (QUAN TRỌNG)
        // (Nếu Entity SanPham của bạn có trường hinhAnh)
        try {
            sp.setHinhAnh(fileName);
            sanPhamRepository.save(sp);
        } catch (Exception e) {
            System.out.println("Lỗi cập nhật ảnh đại diện (Có thể do Entity thiếu trường hinhAnh): " + e.getMessage());
        }

        return savedImage;
    }

    // 6. Lấy danh sách (Phân trang, Tìm kiếm, Lọc danh mục)
    public Page<SanPham> layDanhSachSanPham(String keyword, Integer categoryId, Integer page, Integer size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("id").descending());

        // Sử dụng Query tùy chỉnh đã viết trong Repository để xử lý cả keyword và categoryId
        // (Nếu keyword/category null thì query sẽ tự bỏ qua)
        return sanPhamRepository.timKiemVaLoc(keyword, categoryId, pageable);
    }

    // 7. Cập nhật sản phẩm
    public SanPham capNhatSanPham(Long id, SanPhamRequest request) {
        SanPham sp = sanPhamRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Sản phẩm không tồn tại"));

        if (request.getTen() != null && !request.getTen().isEmpty()) sp.setTen(request.getTen());
        if (request.getMaSku() != null && !request.getMaSku().isEmpty()) sp.setMaSku(request.getMaSku());
        if (request.getGiaGoc() != null) sp.setGiaGoc(request.getGiaGoc());
        if (request.getMoTaNgan() != null) sp.setMoTaNgan(request.getMoTaNgan());
        if (request.getMoTaChiTiet() != null) sp.setMoTaChiTiet(request.getMoTaChiTiet());

        if (request.getIdThuongHieu() != null) {
            sp.setThuongHieu(thuongHieuRepository.findById(request.getIdThuongHieu()).orElse(sp.getThuongHieu()));
        }
        if (request.getIdDanhMuc() != null) {
            sp.setDanhMuc(danhMucRepository.findById(request.getIdDanhMuc()).orElse(sp.getDanhMuc()));
        }
        if (request.getHienThi() != null) {
            sp.setHienThi(request.getHienThi());
        }

        return sanPhamRepository.save(sp);
    }

    // 8. Xóa sản phẩm (Soft Delete)
    public void xoaSanPham(Long id) {
        SanPham sp = sanPhamRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Sản phẩm không tồn tại"));
        sp.setHienThi(false);
        sanPhamRepository.save(sp);
    }
}