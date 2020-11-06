package com.autentication.kotlin.security.services

import com.autentication.kotlin.models.Role
import com.autentication.kotlin.models.User
import com.fasterxml.jackson.annotation.JsonIgnore
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.util.stream.Collectors

class UserDetailsImpl(
        var id: Long?,
        private var username: String,
        var name: String?,
        var email: String?,
        @field:JsonIgnore private var password: String,
        private val authorities: Collection<GrantedAuthority>) : UserDetails {

    override fun getAuthorities(): Collection<GrantedAuthority> {
        return authorities
    }

    override fun getPassword(): String {
        return password
    }

    override fun getUsername(): String {
        return username
    }

    override fun isEnabled(): Boolean {
        return true
    }

    override fun isCredentialsNonExpired(): Boolean {
        return true
    }

    override fun isAccountNonExpired(): Boolean {
        return true
    }

    override fun isAccountNonLocked(): Boolean {
        return true
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || javaClass != other.javaClass) return false

        val user = other as UserDetailsImpl

        return id == user.id

    }

    companion object {
        private const val serialVersionUID = 1L

        fun build(user: User): UserDetailsImpl {
            val authorities: List<GrantedAuthority> = user.roles.stream()
                    .map { role: Role -> SimpleGrantedAuthority(role.name!!.name) }
                    .collect(Collectors.toList())
            return UserDetailsImpl(
                    user.id!!,
                    user.username!!,
                    user.name!!,
                    user.email!!,
                    user.password!!,
                    authorities
            )

        }
    }
}