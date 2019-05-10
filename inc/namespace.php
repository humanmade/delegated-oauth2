<?php

namespace HM\Delegated_Auth;

use WP_Error;
use WP_REST_Request;
use WP_REST_Users_Controller;
use WP_Rewrite;
use WP_User;

/**
 * Remove fetch the user for a given token.
 *
 * @param string $token
 * @return array|WP_Error
 */
function get_remote_user_for_token( string $token ) {
	$response = wp_remote_get( trailingslashit( HM_DELEGATED_AUTH_REST_BASE ) . 'wp/v2/users/me?context=edit&_t=' . time(), [
		'headers' => [
			'Authorization' => "Bearer $token",
			'Accept'        => 'application/json',
		],
	] );

	if ( is_wp_error( $response ) ) {
		return $response;
	}

	$body = json_decode( wp_remote_retrieve_body( $response ), true );

	if ( json_last_error() !== JSON_ERROR_NONE ) {
		return new WP_Error( 'invalid-json', sprintf( 'Unable to parse JSON from response, due to error %s.', json_last_error_msg() ) );
	}
	if ( wp_remote_retrieve_response_code( $response ) !== 200 ) {
		return new WP_Error( 'invalid-access-token', sprintf( 'Invalid access token, received %s (%s)', $body['message'], $body['code'] ) );
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
	$user = new WP_User( $user_id );
	$sync_role = apply_filters( 'delegated_oauth.sync-roles', true );

	if (
		$user->user_email === $remote_user['email'] &&
		( ( $sync_role && $user->roles === $remote_user['roles'] ) || ! $sync_role ) &&
		$user->display_name === $remote_user['name']
	) {
		return true;
	}
	// As we are hooking early into WordPress, not all globals may have been set up yet.
	if ( empty( $GLOBALS['wp_rewrite'] ) ) {
		$GLOBALS['wp_rewrite'] = new WP_Rewrite;
		$GLOBALS['wp_rewrite']->init();
	}
	wp_roles();

	// Rather than using rest_do_request() (which requires a user already be authenicated)
	// we use the controller directly.
	$controller = new WP_REST_Users_Controller;
	$request = new WP_REST_Request( 'POST', '/wp/v2/users/' . $user_id );

	$body = $remote_user;
	$body['id'] = $user_id;

	if ( ! $sync_role ) {
		unset( $body['roles'] );
	}
	$request->set_body_params( $body );
	$user = $controller->update_item( $request );

	if ( is_wp_error( $user ) ) {
		return $user;
	}

	return true;
}

/**
 * Create a WordPress user from a remote WP API user object.
 *
 * @param array $remote_user The WP REST API user object.
 * @return WP_Error|WP_User
 */
function create_user_from_remote_user( array $remote_user, $token ) {
	// As we are hooking early into WordPress, not all globals may have been set up yet.
	if ( empty( $GLOBALS['wp_rewrite'] ) ) {
		$GLOBALS['wp_rewrite'] = new WP_Rewrite;
		$GLOBALS['wp_rewrite']->init();
	}
	wp_roles();

	// Rather than using rest_do_request() (which requires a user already be authenticated)
	// we use the controller directly.
	$controller = new WP_REST_Users_Controller;
	$request = new WP_REST_Request( 'POST', '/wp/v2/users' );

	$body = $remote_user;
	unset( $body['id'] );
	$sync_role = apply_filters( 'delegated_oauth.sync-roles', true );
	if ( ! $sync_role ) {
		unset( $body['roles'] );
	}
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

	return new WP_User( $user['id'] );
}

/**
 * Get a local user for an access token on the delegated site.
 *
 * This will create / update the local WordPress user.
 *
 * @return WP_Error|WP_User
 */
function synchronize_user_for_token( string $token ) {
	$remote_user = get_remote_user_for_token( $token );
	if ( is_wp_error( $remote_user ) ) {
		return $remote_user;
	}
	$local_user = get_user_from_remote_user_id( $remote_user['id'] );

	if ( $local_user ) {
		$update = update_user_from_remote_user( $local_user->ID, $remote_user );
		if ( is_wp_error( $update ) ) {
			return $update;
		}
		return $local_user;
	}
	$local_user = create_user_from_remote_user( $remote_user, $token );

	if ( is_wp_error( $local_user ) ) {
		return $local_user;
	}

	return $local_user;
}
