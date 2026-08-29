const errorCodes = Object.freeze([
    "SUCCESS",
    "UNAUTHORIZED",
    "MISSING_QUERY_PARAMETER",
    "ID_NOT_FOUND",
    "USER_NOT_FOUND",   // <!-- IMPORTANT --!>
    "INTERNAL_ERROR",   // Do not CHANGE the order of the errors
    "WRONG_DATA",       // Do not DELETE any error
    "BANNED",           // In order to ADD an error follow the tip at the bottom
    "MISSING_TOKEN",
    "INVALID_TOKEN",
    "AUTHENTICATED_USER_EMAIL_NOT_FOUND",
    "AUTHENTICATED_USER_BANNED",
    "REGISTRATING_USER_DUPLICATED_REQUEST",
    "EMAIL_ALREADY_REGISTERED",
    "REGISTRATING_USER_INVALID_PASSWORD",
    "INVALID_REGISTRATION_REQUEST",
    "REGISTRATION_CODE_EXPIRED",
    "REGISTRATION_CODE_INVALID",
    "NO_MATCHING_AUTHENTICATED_USER_ID",
    "WRONG_PASSWORD",
    "NOT_FOUND",
    "EMAIL_CHOSEN_NOT_VALID",
    "REGISTRATION_CODE_MAX_ATTEMPTS_REACHED",
    "AUTHENTICATED_USER_DELETED",

    //"ADD_NEW_ERROR_HERE",
]);

const getError = (errorToSearch) => ({code: errorCodes.indexOf(errorToSearch), message: errorToSearch});

module.exports = getError;