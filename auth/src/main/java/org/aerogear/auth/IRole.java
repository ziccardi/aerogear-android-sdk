package org.aerogear.auth;

public interface IRole {
    String getRoleName();
    RoleType getRoleType();
    String getClientID();
}
