package com.vip.oauth2.server.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("vip")
public class VipController {

    @RequestMapping("ok")
    public String ok() {
        return "ok";
    }

    @RequestMapping("error")
    public String error() {
        return "error";
    }
}
