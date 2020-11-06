package com.autentication.kotlin.models

import javax.persistence.*
import javax.validation.constraints.Email
import javax.validation.constraints.NotBlank
import javax.validation.constraints.Size

@Entity
@Table(name = "users",
        uniqueConstraints = arrayOf(
                UniqueConstraint(columnNames = arrayOf("username", "email"))
        )
)
class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Long? = null

    @NotBlank
    @Size(max = 20)
    var username: String? = null

    @NotBlank
    var name: String? = null

    @NotBlank
    @Size(max = 100)
    @Email
    var email: String? = null

    @NotBlank
    @Size(max = 120)
    var password: String? = null

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "users_roles",
            joinColumns = [JoinColumn(name = "user_id")],
            inverseJoinColumns = [JoinColumn(name = "role_id")])
    var roles: Set<Role> = HashSet()

    constructor()

    constructor(id: Long?, username: String?, name: String?, email: String?, password: String?) {
        this.id = id
        this.username = username
        this.name = name
        this.email = email
        this.password = password
    }


}