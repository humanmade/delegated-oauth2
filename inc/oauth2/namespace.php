<?php

namespace HM\Delegated_Auth\OAuth2;

use function HM\Delegated_Auth\synchronize_user_for_token;
use WP_Error;
use WP_Http;
use WP_User;

/**
 * Get the authorization header
 *
 * On certain systems and configurations, the Authorization header will be
 * stripped out by the server or PHP. Typically this is then used to
 * generate `PHP_AUTH_USER`/`PHP_AUTH_PASS` but not passed on. We use
 * `getallheaders` here to try and grab it out instead.
 *
 * @return string|null Authorization header if set, null otherwise
 */
function get_authorization_header() {
	if ( ! empty( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
		return wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] );
	}

	if ( function_exists( 'getallheaders' ) ) {
		$headers = getallheaders();

		// Check for the authorization header case-insensitively
		foreach ( $headers as $key => $value ) {
			if ( strtolower( $key ) === 'authorization' ) {
				return $value;
			}
		}
	}

	return null;
}

/**
 * Extracts the token from the authorization header or the current request.
 *
 * @return string|null Token on success, null on failure.
 */
function get_provided_token() {
	$header = get_authorization_header();
	if ( $header ) {
		return get_token_from_bearer_header( $header );
	}

	$token = get_token_from_request();
	if ( $token ) {
		return $token;
	}

	return null;
}

/**
 * Extracts the token from the given authorization header.
 *
 * @param string $header Authorization header.
 *
 * @return string|null Token on succes, null on failure.
 */
function get_token_from_bearer_header( $header ) {
	if ( is_string( $header ) && preg_match( '/Bearer ([a-zA-Z0-9\-._~\+\/=]+)/', trim( $header ), $matches ) ) {
		return $matches[1];
	}

	return null;
}

/**
 * Extracts the token from the current request.
 *
 * @return string|null Token on succes, null on failure.
 */
function get_token_from_request() {
	if ( empty( $_GET['access_token'] ) ) {
		return null;
	}

	$token = wp_unslash( $_GET['access_token'] );
	if ( is_string( $token ) ) {
		return $token;
	}

	// Got a token, but it's not valid.
	global $delegated_auth_error;
	$delegated_auth_error = create_invalid_token_error( $token );
	return null;
}

/**
 * Try to authenticate if possible.
 *
 * @param int|null $user Existing authenticated user.
 *
 * @return WP_User|int|WP_Error
 */
function attempt_authentication( $user = null ) {
	// Lock against infinite loops when querying the token itself.
	static $is_querying_token = false;
	global $delegated_auth_error;
	$delegated_auth_error = null;

	if ( ! empty( $user ) || $is_querying_token ) {
		return $user;
	}

	// Were we given a token?
	$token_value = get_provided_token();
	if ( empty( $token_value ) ) {
		// No data provided, pass.
		return $user;
	}

	// Attempt to find the token.

	$is_querying_token = true;

	// Locally cache the user for the given access token if it is enabled.
	if ( defined( 'HM_DELEGATED_AUTH_ACCESS_TOKEN_CACHE_TTL' ) ) {
		$cached_id = wp_cache_get( $token_value, 'local_user_id_for_token' );
		if ( $cached_id ) {
			$local_user = new WP_User( $cached_id );
		} else {
			$local_user = synchronize_user_for_token( $token_value );
			if ( is_wp_error( $local_user ) ) {
				$delegated_auth_error = $local_user;
				return $user;
			}
			wp_cache_set( $token_value, $local_user->ID, 'local_user_id_for_token', HM_DELEGATED_AUTH_ACCESS_TOKEN_CACHE_TTL );
		}
	} else {
		$local_user = synchronize_user_for_token( $token_value );
		if ( is_wp_error( $local_user ) ) {
			$delegated_auth_error = $local_user;
			return $user;
		}
	}

	return $local_user->ID;
}

/**
 * Report our errors, if we have any.
 *
 * Attached to the rest_authentication_errors filter. Passes through existing
 * errors registered on the filter.
 *
 * @param WP_Error|null Current error, or null.
 *
 * @return WP_Error|null Error if one is set, otherwise null.
 */
function maybe_report_errors( $error = null ) {
	if ( ! empty( $error ) ) {
		return $error;
	}

	global $delegated_auth_error;
	return $delegated_auth_error;
}

/**
 * Creates an error object for the given invalid token.
 *
 * @param mixed $token Invalid token.
 *
 * @return WP_Error
 */
function create_invalid_token_error( $token ) : WP_Error {
	return new WP_Error(
		'delegated-oauth2.authentication.attempt_authentication.invalid_token',
		__( 'Supplied token is invalid.', 'oauth2' ),
		[
			'status' => WP_Http::FORBIDDEN,
			'token'  => $token,
		]
	);
}
