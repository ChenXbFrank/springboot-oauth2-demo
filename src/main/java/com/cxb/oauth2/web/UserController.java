package com.cxb.oauth2.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 *  用户 controller
 */
@RestController
@RequestMapping("user")
public class UserController {

    @GetMapping("get")
    @PreAuthorize("hasRole('ADMIN')")
    public Object get() {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    @GetMapping("get1")
    @PreAuthorize("hasRole('USER')")
    public Object get1() {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal();

    }
}
