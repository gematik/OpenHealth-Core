/*
 * Copyright 2025 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.openhealth.smartcard.command

val generalAuthenticateStatus =
    mapOf(
        0x0000 to HealthCardResponseStatus.UNKNOWN_STATUS,
        0x9000 to HealthCardResponseStatus.SUCCESS,
        0x6300 to HealthCardResponseStatus.AUTHENTICATION_FAILURE,
        0x6400 to HealthCardResponseStatus.PARAMETER_MISMATCH,
        0x6982 to HealthCardResponseStatus.SECURITY_STATUS_NOT_SATISFIED,
        0x6983 to HealthCardResponseStatus.KEY_EXPIRED,
        0x6985 to HealthCardResponseStatus.NO_KEY_REFERENCE,
        0x6A80 to HealthCardResponseStatus.NUMBER_PRECONDITION_WRONG,
        0x6A81 to HealthCardResponseStatus.UNSUPPORTED_FUNCTION,
        0x6A88 to HealthCardResponseStatus.KEY_NOT_FOUND,
    )

val pinStatus =
    mapOf(
        0x9000 to HealthCardResponseStatus.SUCCESS,
        0x62C1 to HealthCardResponseStatus.TRANSPORT_STATUS_TRANSPORT_PIN,
        0x62C7 to HealthCardResponseStatus.TRANSPORT_STATUS_EMPTY_PIN,
        0x62D0 to HealthCardResponseStatus.PASSWORD_DISABLED,
        0x63C0 to HealthCardResponseStatus.RETRY_COUNTER_COUNT_00,
        0x63C1 to HealthCardResponseStatus.RETRY_COUNTER_COUNT_01,
        0x63C2 to HealthCardResponseStatus.RETRY_COUNTER_COUNT_02,
        0x63C3 to HealthCardResponseStatus.RETRY_COUNTER_COUNT_03,
        0x6982 to HealthCardResponseStatus.SECURITY_STATUS_NOT_SATISFIED,
        0x6988 to HealthCardResponseStatus.PASSWORD_NOT_FOUND,
    )

val manageSecurityEnvironmentStatus =
    mapOf(
        0x9000 to HealthCardResponseStatus.SUCCESS,
        0x6A81 to HealthCardResponseStatus.UNSUPPORTED_FUNCTION,
        0x6A88 to HealthCardResponseStatus.KEY_NOT_FOUND,
    )

val psoComputeDigitalSignatureStatus =
    mapOf(
        0x9000 to HealthCardResponseStatus.SUCCESS,
        0x6400 to HealthCardResponseStatus.KEY_INVALID,
        0x6982 to HealthCardResponseStatus.SECURITY_STATUS_NOT_SATISFIED,
        0x6985 to HealthCardResponseStatus.NO_KEY_REFERENCE,
        0x6A81 to HealthCardResponseStatus.UNSUPPORTED_FUNCTION,
        0x6A88 to HealthCardResponseStatus.KEY_NOT_FOUND,
    )

val readStatus =
    mapOf(
        0x9000 to HealthCardResponseStatus.SUCCESS,
        0x6281 to HealthCardResponseStatus.CORRUPT_DATA_WARNING,
        0x6282 to HealthCardResponseStatus.END_OF_FILE_WARNING,
        0x6981 to HealthCardResponseStatus.WRONG_FILE_TYPE,
        0x6982 to HealthCardResponseStatus.SECURITY_STATUS_NOT_SATISFIED,
        0x6986 to HealthCardResponseStatus.NO_CURRENT_EF,
        0x6A82 to HealthCardResponseStatus.FILE_NOT_FOUND,
        0x6B00 to HealthCardResponseStatus.OFFSET_TOO_BIG,
    )

val selectStatus =
    mapOf(
        0x9000 to HealthCardResponseStatus.SUCCESS,
        0x6283 to HealthCardResponseStatus.FILE_DEACTIVATED,
        0x6285 to HealthCardResponseStatus.FILE_TERMINATED,
        0x6A82 to HealthCardResponseStatus.FILE_NOT_FOUND,
        0x6D00 to HealthCardResponseStatus.INSTRUCTION_NOT_SUPPORTED,
    )

val verifySecretStatus =
    mapOf(
        0x9000 to HealthCardResponseStatus.SUCCESS,
        0x63C0 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_00,
        0x63C1 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_01,
        0x63C2 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_02,
        0x63C3 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_03,
        0x6581 to HealthCardResponseStatus.MEMORY_FAILURE,
        0x6982 to HealthCardResponseStatus.SECURITY_STATUS_NOT_SATISFIED,
        0x6983 to HealthCardResponseStatus.PASSWORD_BLOCKED,
        0x6985 to HealthCardResponseStatus.PASSWORD_NOT_USABLE,
        0x6988 to HealthCardResponseStatus.PASSWORD_NOT_FOUND,
    )

val unlockEgkStatus =
    mapOf(
        0x9000 to HealthCardResponseStatus.SUCCESS,
        0x6983 to HealthCardResponseStatus.PUK_BLOCKED,
        0x63C0 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_00,
        0x63C1 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_01,
        0x63C2 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_02,
        0x63C3 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_03,
        0x63C4 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_04,
        0x63C5 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_05,
        0x63C6 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_06,
        0x63C7 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_07,
        0x63C8 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_08,
        0x63C9 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_09,
        0x6581 to HealthCardResponseStatus.MEMORY_FAILURE,
        0x6982 to HealthCardResponseStatus.SECURITY_STATUS_NOT_SATISFIED,
        0x6985 to HealthCardResponseStatus.WRONG_PASSWORD_LENGTH,
        0x6A88 to HealthCardResponseStatus.PASSWORD_NOT_FOUND,
    )

val changeReferenceDataStatus =
    mapOf(
        0x9000 to HealthCardResponseStatus.SUCCESS,
        0x63C0 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_00,
        0x63C1 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_01,
        0x63C2 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_02,
        0x63C3 to HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_03, // oldSecret wrong
        0x6581 to HealthCardResponseStatus.MEMORY_FAILURE,
        0x6982 to HealthCardResponseStatus.SECURITY_STATUS_NOT_SATISFIED,
        0x6983 to HealthCardResponseStatus.PASSWORD_BLOCKED,
        0x6985 to HealthCardResponseStatus.WRONG_PASSWORD_LENGTH,
        0x6A88 to HealthCardResponseStatus.PASSWORD_NOT_FOUND,
    )

val getRandomValuesStatus =
    mapOf(
        0x9000 to HealthCardResponseStatus.SUCCESS,
        0x6982 to HealthCardResponseStatus.SECURITY_STATUS_NOT_SATISFIED,
    )

/**
 * All response status codes
 * @see "gemSpec_COS_16.2"
 */
enum class HealthCardResponseStatus {
    SUCCESS,
    UNKNOWN_EXCEPTION,
    UNKNOWN_STATUS,
    DATA_TRUNCATED,
    CORRUPT_DATA_WARNING,
    END_OF_FILE_WARNING,
    END_OF_RECORD_WARNING,
    UNSUCCESSFUL_SEARCH,
    FILE_DEACTIVATED,
    FILE_TERMINATED,
    RECORD_DEACTIVATED,
    TRANSPORT_STATUS_TRANSPORT_PIN,
    TRANSPORT_STATUS_EMPTY_PIN,
    PASSWORD_DISABLED,
    AUTHENTICATION_FAILURE,
    NO_AUTHENTICATION,
    RETRY_COUNTER_COUNT_00,
    RETRY_COUNTER_COUNT_01,
    RETRY_COUNTER_COUNT_02,
    RETRY_COUNTER_COUNT_03,
    RETRY_COUNTER_COUNT_04,
    RETRY_COUNTER_COUNT_05,
    RETRY_COUNTER_COUNT_06,
    RETRY_COUNTER_COUNT_07,
    RETRY_COUNTER_COUNT_08,
    RETRY_COUNTER_COUNT_09,
    RETRY_COUNTER_COUNT_10,
    RETRY_COUNTER_COUNT_11,
    RETRY_COUNTER_COUNT_12,
    RETRY_COUNTER_COUNT_13,
    RETRY_COUNTER_COUNT_14,
    RETRY_COUNTER_COUNT_15,
    UPDATE_RETRY_WARNING_COUNT_00,
    UPDATE_RETRY_WARNING_COUNT_01,
    UPDATE_RETRY_WARNING_COUNT_02,
    UPDATE_RETRY_WARNING_COUNT_03,
    UPDATE_RETRY_WARNING_COUNT_04,
    UPDATE_RETRY_WARNING_COUNT_05,
    UPDATE_RETRY_WARNING_COUNT_06,
    UPDATE_RETRY_WARNING_COUNT_07,
    UPDATE_RETRY_WARNING_COUNT_08,
    UPDATE_RETRY_WARNING_COUNT_09,
    UPDATE_RETRY_WARNING_COUNT_10,
    UPDATE_RETRY_WARNING_COUNT_11,
    UPDATE_RETRY_WARNING_COUNT_12,
    UPDATE_RETRY_WARNING_COUNT_13,
    UPDATE_RETRY_WARNING_COUNT_14,
    UPDATE_RETRY_WARNING_COUNT_15,
    WRONG_SECRET_WARNING_COUNT_00,
    WRONG_SECRET_WARNING_COUNT_01,
    WRONG_SECRET_WARNING_COUNT_02,
    WRONG_SECRET_WARNING_COUNT_03,
    WRONG_SECRET_WARNING_COUNT_04,
    WRONG_SECRET_WARNING_COUNT_05,
    WRONG_SECRET_WARNING_COUNT_06,
    WRONG_SECRET_WARNING_COUNT_07,
    WRONG_SECRET_WARNING_COUNT_08,
    WRONG_SECRET_WARNING_COUNT_09,
    WRONG_SECRET_WARNING_COUNT_10,
    WRONG_SECRET_WARNING_COUNT_11,
    WRONG_SECRET_WARNING_COUNT_12,
    WRONG_SECRET_WARNING_COUNT_13,
    WRONG_SECRET_WARNING_COUNT_14,
    WRONG_SECRET_WARNING_COUNT_15,
    ENCIPHER_ERROR,
    KEY_INVALID,
    OBJECT_TERMINATED,
    PARAMETER_MISMATCH,
    MEMORY_FAILURE,
    WRONG_RECORD_LENGTH,
    CHANNEL_CLOSED,
    NO_MORE_CHANNELS_AVAILABLE,
    VOLATILE_KEY_WITHOUT_LCS,
    WRONG_FILE_TYPE,
    SECURITY_STATUS_NOT_SATISFIED,
    COMMAND_BLOCKED,
    KEY_EXPIRED,
    PASSWORD_BLOCKED,
    KEY_ALREADY_PRESENT,
    NO_KEY_REFERENCE,
    NO_PRK_REFERENCE,
    NO_PUK_REFERENCE,
    NO_RANDOM,
    NO_RECORD_LIFE_CYCLE_STATUS,
    PASSWORD_NOT_USABLE,
    WRONG_RANDOM_LENGTH,
    WRONG_RANDOM_OR_NO_KEY_REFERENCE,
    WRONG_PASSWORD_LENGTH,
    NO_CURRENT_EF,
    INCORRECT_SM_DO,
    NEW_FILE_SIZE_WRONG,
    NUMBER_PRECONDITION_WRONG,
    NUMBER_SCENARIO_WRONG,
    VERIFICATION_ERROR,
    WRONG_CIPHER_TEXT,
    WRONG_TOKEN,
    UNSUPPORTED_FUNCTION,
    FILE_NOT_FOUND,
    RECORD_NOT_FOUND,
    DATA_TOO_BIG,
    FULL_RECORD_LIST,
    MESSAGE_TOO_LONG,
    OUT_OF_MEMORY,
    INCONSISTENT_KEY_REFERENCE,
    WRONG_KEY_REFERENCE,
    KEY_NOT_FOUND,
    KEY_OR_PRK_NOT_FOUND,
    PASSWORD_NOT_FOUND,
    PRK_NOT_FOUND,
    PUK_NOT_FOUND,
    DUPLICATED_OBJECTS,
    DF_NAME_EXISTS,
    OFFSET_TOO_BIG,
    INSTRUCTION_NOT_SUPPORTED,
    PUK_BLOCKED,
}
