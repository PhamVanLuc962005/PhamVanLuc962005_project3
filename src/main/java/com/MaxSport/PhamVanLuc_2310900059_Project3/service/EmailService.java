package com.MaxSport.PhamVanLuc_2310900059_Project3.service;

import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.DonHang;
import com.MaxSport.PhamVanLuc_2310900059_Project3.entity.DonHangChiTiet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    public void guiEmailXacNhanDonHang(String emailNguoiNhan, DonHang donHang) {
        SimpleMailMessage message = new SimpleMailMessage();

        message.setTo(emailNguoiNhan);
        message.setSubject("MaxSport - Xác nhận đơn hàng #" + donHang.getMaDon());

        StringBuilder noiDung = new StringBuilder();
        noiDung.append("Cảm ơn bạn đã đặt hàng tại MaxSport!\n\n");
        noiDung.append("Mã đơn hàng: ").append(donHang.getMaDon()).append("\n");
        noiDung.append("Tổng tiền: ").append(donHang.getTongTien()).append(" VNĐ\n");
        noiDung.append("Địa chỉ giao: ").append(donHang.getDiaChiGiaoHang()).append("\n\n");
        noiDung.append("Chi tiết đơn hàng:\n");

        // Liệt kê sản phẩm (Code này giả định bạn đã có list chi tiết trong entity DonHang)
        // Nếu entity DonHang của bạn chưa fetch listChiTiet, bạn cần query thêm hoặc truyền list vào đây
        // Ở đây mình viết mẫu đơn giản:

        noiDung.append("--------------------------------\n");
        noiDung.append("Chúng tôi sẽ sớm liên hệ để giao hàng.\n");
        noiDung.append("Hotline: 0983401587");

        message.setText(noiDung.toString());

        // Gửi mail
        mailSender.send(message);
        System.out.println("Đã gửi mail thành công cho: " + emailNguoiNhan);
    }
}