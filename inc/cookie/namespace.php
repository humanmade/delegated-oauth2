<?php

namespace HM\Delegated_Auth\Cookie;

use function HM\Delegated_Auth\synchronize_user_for_token;
use WP_Error;

function is_enabled() : bool {
	return defined( 'HM_DELEGATED_AUTH_CLIENT_ID' );
}
/**
 * Login page footer for the login link.
 */
function on_login_form() : void {
	?>
	<p><a href="<?php echo esc_url( get_authorize_url() ); ?>">Login with Delegated Auth</a></p>
	<?php
}

function on_load() : void {
	if ( wp_parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH ) !== '/hm-delegated-auth-callback' ) {
		return;
	}

	$code = sanitize_text_field( $_GET['code'] );
	$auth = on_auth_callback( $code );
	if ( is_wp_error( $auth ) ) {
		wp_die( $auth->get_error_message() );
	}
}

function on_auth_callback( string $code ) {
	$args = [
		'client_id'    => HM_DELEGATED_AUTH_CLIENT_ID,
		'redirect_uri' => home_url( '/hm-delegated-auth-callback' ),
		'grant_type'   => 'authorization_code',
		'code'         => $code,
	];
	$response = wp_remote_post( HM_DELEGATED_AUTH_REST_BASE . 'oauth2/access_token', [
		'body' => $args,
	] );
	if ( is_wp_error( $response ) ) {
		return $response;
	}

	$body = json_decode( wp_remote_retrieve_body( $response ), true );

	if ( wp_remote_retrieve_response_code( $response ) !== 200 ) {
		return new WP_Error( 'invalid-access-token', sprintf( 'Invalid access token, recieved %s (%s)', $body['message'], $body['code'] ) );
	}

	$local_user = synchronize_user_for_token( $body['access_token'] );
	if ( is_wp_error( $local_user ) ) {
		return $local_user;
	}

	wp_set_auth_cookie( $local_user->ID, false );
	wp_safe_redirect( admin_url() );
	exit;
}

function get_authorize_url() : string {
	$authorise_url = HM_DELEGATED_AUTH_REST_BASE . 'oauth2/authorize';
	$args = [
		'client_id'     => HM_DELEGATED_AUTH_CLIENT_ID,
		'redirect_uri'  => home_url( '/hm-delegated-auth-callback' ),
		'response_type' => 'code',
	];
	return add_query_arg( $args, $authorise_url );
}

/**
 * When a user authenticates via cookies, check the upstream.
 *
 * @param int|null $user Existing authenticated user.
 *
 * @return int|WP_Error
 */
function attempt_authentication( $user = null ) {
	static $is_querying_token = false;
	if ( ! $user || $is_querying_token ) {
		return $user;
	}

	$is_querying_token = true;

	$token = get_user_meta( $user, 'delegated_oauth2_access_token', true );
	if ( ! $token ) {
		return $user;
	}
	$local_user = synchronize_user_for_token( $token );
	if ( is_wp_error( $local_user ) ) {
		wp_die( $local_user->get_error_message() );
	}

	return $local_user->ID;
}
