package com.openMarket.backend;


import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class ImageSender {
    // 자기 컴퓨터의 파일 시스템의 경로에 따라서 절대경로로 전송.
    private final String filesLocation = "/Users/hwanh2_/Desktop/Sptring Project/Open_Market-main/open-market/src/main/resources/static/images/";

    @RequestMapping("/{img}")
    public ResponseEntity<?> imageSend(@PathVariable String img) {
        String path = filesLocation + img;
        Resource resource = new FileSystemResource(path);
        return ResponseEntity.ok(resource);
    }
}
