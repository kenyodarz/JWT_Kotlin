package com.autentication.kotlin.controllers

import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@CrossOrigin(origins = ["*"], maxAge = 3600)
@RequestMapping("/api/test")
class TestController {

    @GetMapping("all")
    fun allAccess(): ResponseEntity<String> {
        return ResponseEntity.ok("Public Content.")
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('SUPERVISOR') or hasRole('ADMIN')")
    fun userAccess(): String {
        return "User Content."
    }

    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    fun moderatorAccess(): String {
        return "Moderator Board."
    }

    @GetMapping("/sup")
    @PreAuthorize("hasRole('SUPERVISOR')")
    fun supervisorAccess(): String {
        return "Supervisor Board."
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    fun adminAccess(): String {
        return "Admin Board."
    }

}