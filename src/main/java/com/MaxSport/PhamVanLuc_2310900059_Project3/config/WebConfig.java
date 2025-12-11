package com.MaxSport.PhamVanLuc_2310900059_Project3.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Value("${maxsport.upload-dir}")
    private String uploadDir;

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // LOGIC SỬA ĐỔI:
        // 1. Dùng "file:///" (3 dấu gạch) cho Windows.
        // 2. Kiểm tra xem uploadDir có dấu '/' ở cuối chưa để tránh bị 2 dấu '//'.

        String path = "file:///" + uploadDir;
        if (!path.endsWith("/")) {
            path += "/";
        }

        registry.addResourceHandler("/images/**")
                .addResourceLocations(path);
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:5173")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true);
    }
}