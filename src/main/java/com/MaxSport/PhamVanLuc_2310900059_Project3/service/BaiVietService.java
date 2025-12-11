package com.MaxSport.PhamVanLuc_2310900059_Project3.service;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.BaiViet;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.NguoiDung;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.BaiVietRepository;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.NguoiDungRepository;
import com.MaxSport.PhamVanLuc_2310900059_Project3.utils.SlugUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class BaiVietService {

    @Autowired
    private BaiVietRepository baiVietRepository;

    @Autowired
    private NguoiDungRepository nguoiDungRepository;

    // 1. Lấy danh sách bài viết (Mới nhất lên đầu)
    public List<BaiViet> layTatCaBaiViet() {
        return baiVietRepository.findAll(Sort.by(Sort.Direction.DESC, "ngayTao"));
    }

    // 2. Xem chi tiết bài viết theo Slug
    public BaiViet xemChiTiet(String slug) {
        return baiVietRepository.findByDuongDan(slug)
                .orElseThrow(() -> new RuntimeException("Bài viết không tồn tại"));
    }

    // 3. Tạo bài viết mới (Admin)
    public BaiViet taoBaiViet(String tieuDe, String tomTat, String noiDung) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        NguoiDung admin = nguoiDungRepository.findByEmail(username).get();

        BaiViet bv = new BaiViet();
        bv.setTieuDe(tieuDe);

        // Tự động tạo slug từ tiêu đề
        // VD: "Hướng dẫn tập Gym" -> "huong-dan-tap-gym"
        String slug = SlugUtils.toSlug(tieuDe);

        // Kiểm tra trùng slug (Nếu trùng thì thêm số random đuôi - logic đơn giản)
        if (baiVietRepository.findByDuongDan(slug).isPresent()) {
            slug += "-" + System.currentTimeMillis();
        }

        bv.setDuongDan(slug);
        bv.setTomTat(tomTat);
        bv.setNoiDung(noiDung);
        bv.setTacGia(admin);
        bv.setThoiGianDang(LocalDateTime.now());

        return baiVietRepository.save(bv);
    }

    // 4. Xóa bài viết
    public void xoaBaiViet(Long id) {
        baiVietRepository.deleteById(id);
    }
}