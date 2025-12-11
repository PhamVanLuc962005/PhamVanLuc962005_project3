package com.MaxSport.PhamVanLuc_2310900059_Project3.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

@Service
public class FileStorageService {

    @Value("${maxsport.upload-dir}")
    private String uploadDir;

    public String luuFile(MultipartFile file) {
        try {
            String fileName = UUID.randomUUID().toString() + "_" + file.getOriginalFilename();

            // 2. Xác định đường dẫn thư mục lưu (Từ application.properties)
            Path uploadPath = Paths.get(uploadDir);

            // 3. Nếu thư mục chưa có thì tạo mới
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }
            try (InputStream inputStream = file.getInputStream()) {
                Path filePath = uploadPath.resolve(fileName);
                Files.copy(inputStream, filePath, StandardCopyOption.REPLACE_EXISTING);
            }
            return fileName;

        } catch (IOException e) {
            throw new RuntimeException("Không thể lưu file: " + e.getMessage());
        }
    }
}