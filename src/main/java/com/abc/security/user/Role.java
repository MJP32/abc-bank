package com.abc.security.user;

/**
 * Role names. Spring Security expects authorities to be prefixed with "ROLE_"
 * when used with hasRole(...). Keep the prefix off the enum and add it when we
 * map to GrantedAuthority - this avoids leaking the convention through code.
 */
public enum Role {
    USER,
    ADMIN
}
