<?php

namespace HM\Delegated_OAuth2;

use WP_Error;
use WP_REST_Request;
use WP_REST_Users_Controller;
use WP_Rewrite;
use WP_User;
use WP_Http;

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

	$token = $_GET['access_token'];
	if ( is_string( $token ) ) {
		return $token;
	}

	// Got a token, but it's not valid.
	global $delegated_oauth2_error;
	$delegated_oauth2_error = create_invalid_token_error( $token );
	return null;
}

/**
 * Try to authenticate if possible.
 *
 * @param WP_User|null $user Existing authenticated user.
 *
 * @return WP_User|int|WP_Error
 */
function attempt_authentication( $user = null ) {
	// Lock against infinite loops when querying the token itself.
	static $is_querying_token = false;
	global $delegated_oauth2_error;
	$delegated_oauth2_error = null;

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

	$remote_user = get_remote_user_for_token( $token_value );
	if ( is_wp_error( $remote_user ) ) {
		$delegated_oauth2_error = $remote_user;
		return $user;
	}
	$user = get_user_from_remote_user_id( $remote_user['id'] );

	if ( $user ) {
		update_user_from_remote_user( $user->ID, $remote_user );
		return $user->ID;
	}
	$user = create_user_from_remote_user( $remote_user, $token_value );

	if ( is_wp_error( $user ) ) {
		$delegated_oauth2_error = $user;
		return $user;
	}

	$is_querying_token = false;
	return $user->ID;
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

	global $delegated_oauth2_error;
	return $delegated_oauth2_error;
}

/**
 * Creates an error object for the given invalid token.
 *
 * @param mixed $token Invalid token.
 *
 * @return WP_Error
 */
function create_invalid_token_error( $token ) {
	return new WP_Error(
		'delegated-oauth2.authentication.attempt_authentication.invalid_token',
		__( 'Supplied token is invalid.', 'oauth2' ),
		[
			'status' => WP_Http::FORBIDDEN,
			'token'  => $token,
		]
	);
}

/**
 * Remove fetch the user for a given token.
 *
 * @param string $token
 * @return array | WP_Error
 */
function get_remote_user_for_token( string $token ) {
	$response = wp_remote_get( trailingslashit( HM_DELEGATED_OAUTH2_REST_BASE ) . 'wp/v2/users/me?context=edit', [
		'headers' => [
			'Authorization' => "Bearer $token",
			'Accept'        => 'application/json',
		],
	] );

	if ( is_wp_error( $response ) ) {
		return $response;
	}

	$body = json_decode( wp_remote_retrieve_body( $response ), true );

	if ( wp_remote_retrieve_response_code( $response ) !== 200 ) {
		return new WP_Error( 'invalid-access-token', sprintf( 'Invalid access token, recieved %s (%s)', $body['message'], $body['code'] ) );
	}

	return $body;
}

/**
 * Get the WordPress user for a remote user ID.
 *
 * @param int $remote_user_id The remote REST API user id.
 * @return null|WP_User
 */
function get_user_from_remote_user_id( int $remote_user_id ) {
	$users = get_users( [
		'limit' => 1,
		'meta_query' => [
			[
				'key'     => "delegated_oauth2_remote_user_id_{$remote_user_id}",
				'compare' => 'EXISTS',
			],
		],
	] );

	if ( ! $users ) {
		return null;
	}

	return $users[0];
}

/**
 * Update the local WordPress user from a remote user.
 *
 * @param int   $user_id
 * @param array $remote_user
 */
function update_user_from_remote_user( int $user_id, array $remote_user ) {
	update_user_meta( $user['id'], 'hm_stack_applications', $remote_user['applications'] );
}

/**
 * Create a WordPress user from a remote WP API user object.
 *
 * @param array $remote_user The WP REST API user object.
 * @return WP_Error|WP_User
 */
function create_user_from_remote_user( array $remote_user ) {
	// As we are hooking early into WordPress, not all globals may have been set up yet.
	if ( empty( $GLOBALS['wp_rewrite'] ) ) {
		$GLOBALS['wp_rewrite'] = new WP_Rewrite;
		$GLOBALS['wp_rewrite']->init();
	}
	wp_roles();

	// Rather than using rest_do_request() (which requires a user already be authenicated)
	// we use the controller directly.
	$controller = new WP_REST_Users_Controller;
	$request = new WP_REST_Request( 'POST', '/wp/v2/users' );

	$body = $remote_user;
	unset( $body['id'] );
	$request->set_body_params( $body );
	$user = $controller->create_item( $request );

	if ( is_wp_error( $user ) ) {
		return $user;
	}
	$user = $user->get_data();

	update_user_meta( $user['id'], 'delegated_oauth2_access_token', $token );
	update_user_meta( $user['id'], 'delegated_oauth2_access_token_' . $token, time() );
	update_user_meta( $user['id'], 'delegated_oauth2_remote_user_id', $remote_user['id'] );
	update_user_meta( $user['id'], 'delegated_oauth2_remote_user_id_' . $remote_user['id'], time() );
	update_user_meta( $user['id'], 'hm_stack_applications', $remote_user['applications'] );

	return new WP_User( $user['id'] );
}
