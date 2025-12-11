package com.MaxSport.PhamVanLuc_2310900059_Project3.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {

    // Khóa bí mật để ký tên (Không được để lộ ra ngoài)
    // Trong thực tế nên để trong application.properties
    private static final String SECRET_KEY = "MaxSport_PhamVanLuc_SecretKey_Demo_Project_123456";

    // Thời gian hết hạn của Token (ví dụ: 24 giờ)
    private static final long EXPIRATION_TIME = 86400000L;

    private final Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());

    // Hàm tạo Token từ Tên đăng nhập
    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
    // 1. Lấy username từ Token
    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    // 2. Kiểm tra Token có hợp lệ không
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // Hàm phụ trợ để lấy thông tin chi tiết
    private Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}