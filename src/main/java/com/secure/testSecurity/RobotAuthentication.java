package com.secure.testSecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class RobotAuthentication implements Authentication {
    private final boolean isAuthenticated;
    private final List<GrantedAuthority> authorities;
    private final String password;

    private RobotAuthentication(List<GrantedAuthority> authorities,String password) {
        this.password = password;
        this.authorities=authorities;
        this.isAuthenticated=password==null;
    }

    public static RobotAuthentication unauthenticated(String password){
        return new RobotAuthentication(Collections.emptyList(),password);
    }

    public static RobotAuthentication authenticated(){
        return new RobotAuthentication(AuthorityUtils.createAuthorityList("ROLE_robot"),null);
    }



    @Override
    public String getName() {
        return "Mr Robot";
    }

    @Override
    public Object getPrincipal() {
        return getName();
    }


    @Override
    public boolean isAuthenticated() {
        return isAuthenticated;
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return null;
    }


    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        throw  new IllegalArgumentException("Don't do that!!!");
    }
    
    public String getPassword(){
        return password;
    }


}
