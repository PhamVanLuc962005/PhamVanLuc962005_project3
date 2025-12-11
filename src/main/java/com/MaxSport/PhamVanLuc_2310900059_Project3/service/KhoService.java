package com.MaxSport.PhamVanLuc_2310900059_Project3.service;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.NhapKhoRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.KhoHang;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.SanPhamPhienBan;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.TonKho;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.KhoHangRepository;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.SanPhamPhienBanRepository;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.TonKhoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class KhoService {

    @Autowired
    private TonKhoRepository tonKhoRepository;

    @Autowired
    private KhoHangRepository khoHangRepository;

    @Autowired
    private SanPhamPhienBanRepository phienBanRepository;

    // Mặc định nhập vào kho ID = 1
    private final Integer ID_KHO_MAC_DINH = 1;

    @Transactional
    public TonKho nhapKho(NhapKhoRequest request) {
        // 1. Kiểm tra kho và phiên bản có tồn tại không
        KhoHang kho = khoHangRepository.findById(ID_KHO_MAC_DINH)
                .orElseThrow(() -> new RuntimeException("Kho hàng không tồn tại"));

        SanPhamPhienBan phienBan = phienBanRepository.findById(request.getIdPhienBan())
                .orElseThrow(() -> new RuntimeException("Phiên bản sản phẩm không tồn tại"));

        // 2. Tìm xem trong kho đã có sản phẩm này chưa
        TonKho tonKho = tonKhoRepository.findByKhoHangIdAndSanPhamPhienBanId(ID_KHO_MAC_DINH, request.getIdPhienBan())
                .orElse(null);

        if (tonKho == null) {
            // Nếu chưa có -> Tạo mới
            tonKho = new TonKho();
            tonKho.setKhoHang(kho);
            tonKho.setSanPhamPhienBan(phienBan);
            tonKho.setSoLuong(request.getSoLuong());
            tonKho.setDaGiu(0);
        } else {
            // Nếu có rồi -> Cộng thêm số lượng
            tonKho.setSoLuong(tonKho.getSoLuong() + request.getSoLuong());
        }

        return tonKhoRepository.save(tonKho);
    }
    // Hàm xem số lượng tồn của 1 phiên bản cụ thể (Public cho khách xem)
    public Integer xemSoLuongTon(Long idPhienBan) {
        // Tìm trong kho mặc định (ID = 1)
        TonKho tonKho = tonKhoRepository.findByKhoHangIdAndSanPhamPhienBanId(ID_KHO_MAC_DINH, idPhienBan)
                .orElse(null);

        // Nếu chưa có trong bảng kho -> Coi như bằng 0
        return tonKho != null ? tonKho.getSoLuong() : 0;
    }
}