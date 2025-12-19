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
import java.util.Collections; // Import thêm thư viện này

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
                        // 1. QUAN TRỌNG: Cho phép tất cả request OPTIONS (Pre-flight)
                        // Giúp trình duyệt không bị chặn khi hỏi CORS
                        // -------------------------------------------------------------
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // -------------------------------------------------------------
                        // 2. CÁC API CÔNG KHAI
                        // -------------------------------------------------------------
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/images/**").permitAll()
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/banner/hien-thi").permitAll()
                        .requestMatchers("/api/payment/**").permitAll()

                        // --- SẢN PHẨM & KHO ---
                        .requestMatchers(HttpMethod.GET, "/api/san-pham/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/kho/xem-ton-kho").permitAll()

                        // --- ĐÁNH GIÁ & BÀI VIẾT ---
                        .requestMatchers(HttpMethod.GET, "/api/danh-gia/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/bai-viet/**").permitAll()

                        // --- DANH MỤC & THƯƠNG HIỆU ---
                        .requestMatchers(HttpMethod.GET, "/api/danh-muc/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/thuong-hieu/**").permitAll()

                        // -------------------------------------------------------------
                        // 3. CÁC API DÀNH RIÊNG CHO ADMIN
                        // -------------------------------------------------------------
                        .requestMatchers("/api/danh-muc/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/thuong-hieu/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/kho/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/don-hang/quan-ly/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/thong-ke/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/nguoi-dung/quan-ly/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/banner/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/ma-giam-gia/**").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/bai-viet/**").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/bai-viet/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/khieu-nai/quan-ly/**").hasAuthority("ADMIN")

                        // -------------------------------------------------------------
                        // 4. CÁC API CẦN ĐĂNG NHẬP
                        // -------------------------------------------------------------
                        .requestMatchers(HttpMethod.POST, "/api/danh-gia/**").authenticated()
                        .requestMatchers("/api/nguoi-dung/**").authenticated()
                        .requestMatchers("/api/khieu-nai/**").authenticated()

                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOriginPatterns(Collections.singletonList("*"));

        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}