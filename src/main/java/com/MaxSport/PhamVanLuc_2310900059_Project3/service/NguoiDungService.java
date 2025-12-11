package com.MaxSport.PhamVanLuc_2310900059_Project3.service;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.DangKyRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.DangNhapRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.CapNhatThongTinRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.request.DoiMatKhauRequest;
import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.response.JwtResponse;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.NguoiDung;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.VaiTro;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.NguoiDungRepository;
import com.MaxSport.PhamVanLuc_2310900059_Project3.repository.VaiTroRepository;
import com.MaxSport.PhamVanLuc_2310900059_Project3.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class NguoiDungService {

    @Autowired
    private NguoiDungRepository nguoiDungRepository;

    @Autowired
    private VaiTroRepository vaiTroRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtils jwtUtils;

    // 1. Đăng Ký (Sửa lại: Chỉ check trùng Email)
    public NguoiDung dangKyNguoiDung(DangKyRequest request) {
        // Kiểm tra trùng Email (Quan trọng nhất)
        if (nguoiDungRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email đã được sử dụng!");
        }

        // BỎ kiểm tra trùng tên đăng nhập (Vì tên đăng nhập giờ được phép trùng)

        // Tạo Entity
        NguoiDung user = new NguoiDung();
        user.setTenDangNhap(request.getTenDangNhap());
        user.setEmail(request.getEmail());
        user.setSoDienThoai(request.getSoDienThoai());
        user.setHoTen(request.getHoTen());
        user.setDiaChi(request.getDiaChi());

        // Mã hóa mật khẩu
        user.setMatKhauHash(passwordEncoder.encode(request.getPassword()));

        // Gán quyền USER
        Set<VaiTro> roles = new HashSet<>();
        VaiTro roleUser = vaiTroRepository.findByTen("USER")
                .orElseThrow(() -> new RuntimeException("Lỗi: Không tìm thấy quyền USER. Hãy INSERT dữ liệu vào bảng vai_tro!"));
        roles.add(roleUser);
        user.setVaiTro(roles);

        return nguoiDungRepository.save(user);
    }

    // 2. Đăng Nhập (Sửa lại: Tìm bằng Email)
    public JwtResponse dangNhap(DangNhapRequest request) {
        // Tìm user theo EMAIL
        NguoiDung user = nguoiDungRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Email không tồn tại hoặc chưa đăng ký!"));

        // Kiểm tra mật khẩu
        if (!passwordEncoder.matches(request.getPassword(), user.getMatKhauHash())) {
            throw new RuntimeException("Mật khẩu không chính xác!");
        }

        if (Boolean.FALSE.equals(user.getKichHoat())) {
            throw new RuntimeException("Tài khoản của bạn đã bị khóa! Vui lòng liên hệ Admin.");
        }

        // Tạo Token dựa trên EMAIL
        String token = jwtUtils.generateToken(user.getEmail());

        // Lấy quyền
        String role = user.getVaiTro().stream().findFirst().get().getTen();

        // Trả về kết quả (Vẫn trả về tenDangNhap để hiển thị "Xin chào..." ở Frontend)
        return new JwtResponse(token, user.getTenDangNhap(), role);
    }

    // 3. Cập nhật thông tin (Sửa lại: Lấy ID từ Email trong Token)
    public NguoiDung capNhatThongTin(CapNhatThongTinRequest request) {
        // Lấy email từ Security Context (Do lúc login ta dùng email làm định danh)
        String email = SecurityContextHolder.getContext().getAuthentication().getName();

        NguoiDung user = nguoiDungRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy người dùng"));

        if (request.getHoTen() != null) user.setHoTen(request.getHoTen());
        if (request.getDiaChi() != null) user.setDiaChi(request.getDiaChi());
        if (request.getSoDienThoai() != null) user.setSoDienThoai(request.getSoDienThoai());

        // Nếu đổi email thì cần check trùng lại (Logic nâng cao, tạm thời chưa xử lý ở đây)

        return nguoiDungRepository.save(user);
    }

    // 4. Đổi mật khẩu (Sửa lại: Tìm user bằng Email)
    public void doiMatKhau(DoiMatKhauRequest request) {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();

        NguoiDung user = nguoiDungRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy người dùng"));

        if (!passwordEncoder.matches(request.getMatKhauCu(), user.getMatKhauHash())) {
            throw new RuntimeException("Mật khẩu cũ không chính xác!");
        }

        if (!request.getMatKhauMoi().equals(request.getXacNhanMatKhau())) {
            throw new RuntimeException("Mật khẩu xác nhận không khớp!");
        }

        user.setMatKhauHash(passwordEncoder.encode(request.getMatKhauMoi()));
        nguoiDungRepository.save(user);
    }
    // 3. Lấy danh sách tất cả người dùng (Cho Admin)
    public Page<NguoiDung> layDanhSachNguoiDung(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("id").descending());
        return nguoiDungRepository.findAll(pageable);
    }

    // 4. Khóa / Mở khóa người dùng
    public void doiTrangThaiKichHoat(Long id) {
        NguoiDung user = nguoiDungRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Người dùng không tồn tại"));

        // Đảo ngược trạng thái (True -> False, False -> True)
        if (user.getKichHoat() == null) user.setKichHoat(true);
        user.setKichHoat(!user.getKichHoat());

        nguoiDungRepository.save(user);
    }
}