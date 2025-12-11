package com.MaxSport.PhamVanLuc_2310900059_Project3.service;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.Banner;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.BannerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Service
public class BannerService {

    @Autowired
    private BannerRepository bannerRepository;

    @Autowired
    private FileStorageService fileStorageService;

    // 1. Lấy danh sách Banner hiển thị (Cho trang chủ - Public)
    public List<Banner> layBannerTrangChu() {
        return bannerRepository.findByKichHoatTrueOrderByUuTienDesc();
    }

    // 2. Lấy tất cả Banner (Cho Admin)
    public List<Banner> layTatCaBanner() {
        return bannerRepository.findAll();
    }

    // 3. Thêm Banner mới
    public Banner themBanner(String tieuDe, String lienKet, Integer uuTien, MultipartFile file) {
        String hinhAnhPath = fileStorageService.luuFile(file); // Upload ảnh

        Banner banner = new Banner();
        banner.setTieuDe(tieuDe);
        banner.setLienKet(lienKet);
        banner.setUuTien(uuTien != null ? uuTien : 0);
        banner.setHinhAnh(hinhAnhPath);
        banner.setKichHoat(true); // Mặc định bật

        return bannerRepository.save(banner);
    }

    // 4. Xóa Banner
    public void xoaBanner(Integer id) {
        bannerRepository.deleteById(id);
    }

    // 5. Bật/Tắt Banner
    public Banner toggleBanner(Integer id) {
        Banner banner = bannerRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Banner không tồn tại"));

        banner.setKichHoat(!banner.getKichHoat()); // Đảo ngược trạng thái
        return bannerRepository.save(banner);
    }
}