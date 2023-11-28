package com.securebank.controller;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.securebank.model.Notice;
import com.securebank.repository.NoticeRepository;

@RestController
public class NoticesController {

    @Autowired
    private NoticeRepository noticeRepository;

    @GetMapping("/notices")
    public ResponseEntity<List<Notice>> getNotices() {
        List<Notice> notices = noticeRepository.findAllActiveNotices();
        if (notices != null ) {
            return ResponseEntity.ok()
                    /**
                     * .cacheControl(CacheControl.maxAge(60, TimeUnit.SECONDS)): Sets the Cache-Control header in the HTTP response.
                     * In this case, it's setting the maximum age of the response to 60 seconds. This means that the client (e.g., a web browser) is allowed to cache the response for up to 60 seconds before making a new request to the server.
                     */
                    .cacheControl(CacheControl.maxAge(60, TimeUnit.SECONDS))
                    .body(notices);
        }else {
            return null;
        }
    }

}
