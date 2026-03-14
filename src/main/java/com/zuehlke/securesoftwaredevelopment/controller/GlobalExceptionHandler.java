package com.zuehlke.securesoftwaredevelopment.controller;

import com.zuehlke.securesoftwaredevelopment.config.SecurityUtil;
import com.zuehlke.securesoftwaredevelopment.domain.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.servlet.http.HttpServletRequest;

@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AccessDeniedException.class)
    public String handleAccessDeniedException(AccessDeniedException ex, HttpServletRequest request) {
        User user = SecurityUtil.getCurrentUser();
        String userId = user != null ? String.valueOf(user.getId()) : "anonymous";
        LOG.warn("Access denied: userId={}, uri={}, method={}, message={}",
                userId, request.getRequestURI(), request.getMethod(), ex.getMessage());
        throw ex;
    }

    @ExceptionHandler(Exception.class)
    public String handleException(Exception ex, HttpServletRequest request) {
        User user = SecurityUtil.getCurrentUser();
        String userId = user != null ? String.valueOf(user.getId()) : "anonymous";
        LOG.error("Unhandled exception: userId={}, uri={}, method={}",
                userId, request.getRequestURI(), request.getMethod(), ex);
        return "error";
    }
}
