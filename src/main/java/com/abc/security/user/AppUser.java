package com.abc.security.user;

import jakarta.persistence.*;

import java.util.EnumSet;
import java.util.Set;

@Entity
@Table(name = "app_user")
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    /** BCrypt-encoded password. Never store plaintext. */
    @Column(nullable = false)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER, targetClass = Role.class)
    @Enumerated(EnumType.STRING)
    @CollectionTable(name = "app_user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role", nullable = false)
    private Set<Role> roles = EnumSet.noneOf(Role.class);

    @Column(nullable = false)
    private boolean enabled = true;

    protected AppUser() {}

    public AppUser(String username, String encodedPassword, Set<Role> roles) {
        this.username = username;
        this.password = encodedPassword;
        this.roles = EnumSet.copyOf(roles);
    }

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public Set<Role> getRoles() { return roles; }
    public boolean isEnabled() { return enabled; }

    public void setPassword(String encodedPassword) { this.password = encodedPassword; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
}
