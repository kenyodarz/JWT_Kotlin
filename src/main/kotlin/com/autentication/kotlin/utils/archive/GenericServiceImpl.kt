package com.autentication.kotlin.utils.archive

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Service
import java.io.Serializable
import java.util.function.Consumer

@Service
abstract class GenericServiceImpl <T, ID: Serializable> : GenericServiceAPI<T, ID>{
    override fun getAll(): List<T> {
        val returnList: MutableList<T> = ArrayList()
        getRepository().findAll().forEach(Consumer { e: T -> returnList.add(e) })
        return returnList
    }

    override fun getE(id: ID): T {
        // Obtenemos un Optional de Java8
        val optional = getRepository().findById(id)
        // Retornamos null en caso de que no hallemos el objeto
        return optional.orElse(null)
    }

    override fun save(entity: T): T {
        return getRepository().save(entity)
    }

    override fun delete(id: ID) {
        return getRepository().deleteById(id)
    }

    abstract override fun getRepository(): JpaRepository<T, ID>
}
