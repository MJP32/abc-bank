package com.abc.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Server-rendered pages for the form-login chain.
 * Demonstrates URL-based access (configured in SecurityConfig) and how to
 * read the authenticated principal in a controller via @AuthenticationPrincipal.
 */
@Controller
public class PageController {

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal UserDetails user, Model model) {
        model.addAttribute("username", user.getUsername());
        model.addAttribute("authorities", user.getAuthorities());
        return "dashboard";
    }

    @GetMapping("/admin")
    public String admin(Model model) {
        model.addAttribute("message", "Admin-only area. Reached because URL rule requires ROLE_ADMIN.");
        return "admin";
    }
}
