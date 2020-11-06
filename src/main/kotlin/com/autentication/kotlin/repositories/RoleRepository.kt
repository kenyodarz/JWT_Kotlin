package com.autentication.kotlin.repositories

import com.autentication.kotlin.models.ERole
import com.autentication.kotlin.models.Role
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.*

@Repository
interface RoleRepository: JpaRepository<Role, Long> {
    fun findByName(name: ERole): Optional<Role>
}