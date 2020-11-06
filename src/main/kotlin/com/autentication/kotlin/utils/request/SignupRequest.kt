package com.autentication.kotlin.utils.request

import javax.validation.constraints.Email
import javax.validation.constraints.NotBlank
import javax.validation.constraints.Size

class SignupRequest {

    @NotBlank
    @Size(min = 3, max = 20)
    var username: String? = null

    @NotBlank
    @Size(min = 3, max = 120)
    var name: String? = null

    @NotBlank
    @Size(max = 80)
    @Email
    var email: String? = null

    @NotBlank
    @Size(min = 6, max = 40)
    var password: String? = null

}