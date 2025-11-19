/*
 * Copyright (c) 2020 All Rights Reserved, Ingenico SA.
 */
package des

/**
 * The result of each step
 * [T] generic type of success data
 */
sealed class DesResult<out T : Any> {

    /**
     * The success result of each step
     * [T] generic type of success data
     * Example:
     * Result.Success(StepAOutput())
     */
    data class Success<out T : Any>(val data: T) : DesResult<T>()

    /**
     * The error result of each step
     * @property errorCode: The error code of error
     * Example:
     * 1. Return error code: Result.Error(errorCode = UNKNOWN_ERROR)
     * 2. Return subtype of error:
     * data class UnknownError() : Result.Error()
     *
     * Result.Error(UnknownError())
     */
    open class Error(val errorCode: Int = -1, val errorMessage: String = "") : DesResult<Nothing>()

    /**
     * Check [Result] is success or not
     * @return [Boolean] true is success, false is otherwise
     */
    fun isSuccess(): Boolean {
        return this is Success
    }

    /**
     * Return data of [Result.Success]
     * @return [T] generic type of success data
     */
    fun toData(): T {
        return (this as Success).data
    }

    /**
     * Check [Result] is error or not
     * @return [Boolean] true is error, false is otherwise
     */
    fun isError(): Boolean {
        return this is Error
    }

    /**
     * Cast to specific type [Result.Error]
     * @return [Result.Error] cast [Result] common type to specific [Result.Error]
     */
    fun toError(): Error {
        return this as Error
    }

    override fun toString(): String {
        return when (this) {
            is Success -> "Success[data=$data]"
            is Error -> "Error[errorCode=$errorCode, errorClass=${this::class.java.name}]"
        }
    }
}
