package com.secure.testSecurity;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

public class RobotFilter extends OncePerRequestFilter {
    private  final String ROBOT_HEADER = "x-robot-password";

    private final AuthenticationManager authenticationManager;

    public RobotFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        System.out.println("@@@--->Inside RobotFilter---->");


        if (!Collections.list(request.getHeaderNames()).contains(ROBOT_HEADER)) {
            filterChain.doFilter(request,response);
            return;
        }

        var robotPassowd= request.getHeader(ROBOT_HEADER);

        var authRequest=RobotAuthentication.unauthenticated(robotPassowd);

        try {
            var authentication=authenticationManager.authenticate(authRequest);
            var newContext= SecurityContextHolder.createEmptyContext();
            newContext.setAuthentication(authentication);
            SecurityContextHolder.setContext(newContext);
            filterChain.doFilter(request,response);
            return;
        } catch (AuthenticationException e){
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setHeader("Content-type","text/plane:charset=utf-8");
            response.getWriter().println(e.getMessage());
            return;
        }


    }
}
