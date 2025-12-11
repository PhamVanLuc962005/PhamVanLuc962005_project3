package com.MaxSport.PhamVanLuc_2310900059_Project3.utils;

import java.text.Normalizer;
import java.util.regex.Pattern;

public class SlugUtils {

    public static String toSlug(String input) {
        if (input == null) return "";

        // 1. Chuyển thành chữ thường
        String str = input.toLowerCase();

        // 2. Xóa dấu tiếng Việt (Normalizer)
        String temp = Normalizer.normalize(str, Normalizer.Form.NFD);
        Pattern pattern = Pattern.compile("\\p{InCombiningDiacriticalMarks}+");
        str = pattern.matcher(temp).replaceAll("");

        // 3. Thay thế đ -> d
        str = str.replace("đ", "d");

        // 4. Xóa ký tự đặc biệt, thay khoảng trắng bằng gạch ngang
        str = str.replaceAll("[^a-z0-9\\s-]", "");
        str = str.replaceAll("\\s+", "-");

        return str;
    }
}