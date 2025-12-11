package com.MaxSport.PhamVanLuc_2310900059_Project3.controller;

import com.MaxSport.PhamVanLuc_2310900059_Project3.dto.response.PaymentResponse;
import com.MaxSport.PhamVanLuc_2310900059_Project3.service.PaymentService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/payment")
public class PaymentController {

    @Autowired
    private PaymentService paymentService;

    // 1. Tạo Link Thanh Toán
    // Gọi API này với số tiền, nó sẽ trả về Link VNPAY
    // http://localhost:8080/api/payment/create_payment?amount=100000&orderInfo=Thanh toan don hang
    @GetMapping("/create_payment")
    public ResponseEntity<?> createPayment(HttpServletRequest request,
                                           @RequestParam long amount,
                                           @RequestParam(defaultValue = "Thanh toan don hang") String orderInfo) {
        PaymentResponse response = paymentService.createVnPayPayment(request, amount, "NCB", orderInfo);
        return ResponseEntity.ok(response);
    }

    // 2. Xử lý sau khi thanh toán xong (VNPAY gọi về đây)
    // http://localhost:8080/api/payment/vnpay_return
    @GetMapping("/vnpay_return")
    public ResponseEntity<?> returnPayment(HttpServletRequest request) {
        String vnp_ResponseCode = request.getParameter("vnp_ResponseCode");
        String vnp_TxnRef = request.getParameter("vnp_TxnRef"); // Mã đơn hàng phía mình
        String vnp_Amount = request.getParameter("vnp_Amount"); // Số tiền

        if ("00".equals(vnp_ResponseCode)) {
            // Thanh toán thành công
            // TODO: Tại đây bạn sẽ gọi Service để cập nhật trạng thái đơn hàng trong DB thành "DA_THANH_TOAN"
            return ResponseEntity.ok("Giao dịch thành công! Mã đơn: " + vnp_TxnRef + " - Số tiền: " + vnp_Amount);
        } else {
            return ResponseEntity.badRequest().body("Giao dịch thất bại!");
        }
    }
}