package com.cxb.oauth2.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 *  部门controller
 */
@RestController
@RequestMapping("dept")
public class DeptController {

    @GetMapping("get")
    @PreAuthorize("hasRole('ADMIN')")
    public Object get() {
        return "manage dept";
    }

    @GetMapping("get1")
    @PreAuthorize("hasRole('USER')")
    public Object get1() {
        return "it dept";

    }
}
