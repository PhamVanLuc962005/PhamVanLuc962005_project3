package com.MaxSport.PhamVanLuc_2310900059_Project3.config;

import com.MaxSport.PhamVanLuc_2310900059_Project3.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        // -------------------------------------------------------------
                        // 1. CÁC API CÔNG KHAI (Ai cũng truy cập được)
                        // -------------------------------------------------------------
                        .requestMatchers("/api/auth/**").permitAll() // Đăng nhập/Đăng ký
                        .requestMatchers("/images/**").permitAll()   // Xem ảnh
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll() // Swagger
                        .requestMatchers(HttpMethod.GET, "/api/banner/hien-thi").permitAll() // Xem banner
                        .requestMatchers("/api/payment/**").permitAll() // Thanh toán

                        // --- SẢN PHẨM & KHO (Xem thì mở, sửa thì Admin) ---
                        .requestMatchers(HttpMethod.GET, "/api/san-pham/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/kho/xem-ton-kho").permitAll()

                        // --- ĐÁNH GIÁ & BÀI VIẾT (Xem thì mở) ---
                        .requestMatchers(HttpMethod.GET, "/api/danh-gia/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/bai-viet/**").permitAll()

                        // --- DANH MỤC & THƯƠNG HIỆU (SỬA PHẦN NÀY) ---
                        // Cho phép xem danh sách
                        .requestMatchers(HttpMethod.GET, "/api/danh-muc/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/thuong-hieu/**").permitAll()

                        // -------------------------------------------------------------
                        // 2. CÁC API DÀNH RIÊNG CHO ADMIN
                        // -------------------------------------------------------------

                        // Quản lý Danh mục & Thương hiệu (POST, PUT, DELETE)
                        // Vì dòng GET đã khai báo ở trên rồi, nên dòng này sẽ bắt các method còn lại
                        .requestMatchers("/api/danh-muc/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/thuong-hieu/**").hasAuthority("ADMIN")

                        // Quản lý Sản phẩm & Kho
                        .requestMatchers("/api/kho/**").hasAuthority("ADMIN")

                        // Quản lý Đơn hàng & Thống kê
                        .requestMatchers("/api/don-hang/quan-ly/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/thong-ke/**").hasAuthority("ADMIN")

                        // Quản lý Người dùng
                        .requestMatchers("/api/nguoi-dung/quan-ly/**").hasAuthority("ADMIN")

                        // Quản lý khác (Banner, Mã giảm giá, Bài viết)
                        .requestMatchers("/api/banner/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/ma-giam-gia/**").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/bai-viet/**").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/bai-viet/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/khieu-nai/quan-ly/**").hasAuthority("ADMIN")

                        // -------------------------------------------------------------
                        // 3. CÁC API CẦN ĐĂNG NHẬP (User hoặc Admin đều được)
                        // -------------------------------------------------------------
                        .requestMatchers(HttpMethod.POST, "/api/danh-gia/**").authenticated()
                        .requestMatchers("/api/nguoi-dung/**").authenticated() // Sửa profile
                        .requestMatchers("/api/khieu-nai/**").authenticated()  // Gửi khiếu nại

                        // Tất cả các request còn lại bắt buộc phải đăng nhập
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:5173"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}