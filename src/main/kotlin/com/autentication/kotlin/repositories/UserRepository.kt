package com.autentication.kotlin.repositories

import com.autentication.kotlin.models.User
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.Optional

@Repository
interface UserRepository : JpaRepository<User, Long> {

    fun findByUsername(username: String): Optional<User>

    fun existsByUsername(username: String): Boolean

    fun existsByEmail(email: String): Boolean
}