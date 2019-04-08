<?php

namespace HM\Delegated_Auth\Cookie;

use function HM\Delegated_Auth\synchronize_user_for_token;
use WP_Error;

defined( 'HM_DELEGATED_AUTH_LOGIN_TEXT' ) or define( 'HM_DELEGATED_AUTH_LOGIN_TEXT', 'Log In with Delegated Auth' );

/**
 * Check if the plugin is enabled
 *
 * Setup for the plugin requires HM_DELEGATED_AUTH_CLIENT_ID be defined.
 */
function is_enabled() : bool {
	return defined( 'HM_DELEGATED_AUTH_CLIENT_ID' );
}
/**
 * Login page footer for the login link.
 */
function on_login_form() {
	if ( defined( 'HM_DELEGATED_AUTH_LOGIN_TEXT' ) && is_string( HM_DELEGATED_AUTH_LOGIN_TEXT ) ) { ?>
		<p><a href="<?php echo esc_url( get_authorize_url() ); ?>"><?php echo esc_html( HM_DELEGATED_AUTH_LOGIN_TEXT ); ?></a></p>
		<?php
	}
}

/**
 * Load hook to check for the oauth2 redirect request.
 */
function on_load() {
	if ( wp_parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH ) !== '/hm-delegated-auth-callback' ) {
		return;
	}

	if ( is_multisite() && isset( $_GET['site'] ) ) {
		// Find the site's callback.
		$site = absint( $_GET['site'] );
		$url = get_home_url( $site, '/hm-delegated-auth-callback' );

		// Add query arguments to the redirect.
		wp_parse_str( $_SERVER['QUERY_STRING'], $args );
		$with_args = remove_query_arg( 'site', add_query_arg( $args, $url ) );

		wp_redirect( $with_args );
		exit;
	}

	$code = sanitize_text_field( $_GET['code'] );
	$auth_user = on_auth_callback( $code );
	if ( is_wp_error( $auth_user ) ) {
		wp_die( $auth_user );
	}
	wp_set_auth_cookie( $auth_user->ID, false );
	wp_safe_redirect( admin_url() );
	exit;
}

/**
 * Handle the oauth2 redirect_url request.
 *
 * @param  string           $code The oauth2 response code
 * @return WP_Error|WP_User
 */
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

	if ( json_last_error() !== JSON_ERROR_NONE ) {
		return new WP_Error( 'invalid-json', sprintf( 'Unable to parse JSON from response, due to error %s.', json_last_error_msg() ) );
	}
	if ( wp_remote_retrieve_response_code( $response ) !== 200 ) {
		return new WP_Error( 'invalid-access-token', sprintf( 'Invalid access token, received %s (%s)', $body['message'], $body['code'] ) );
	}

	$local_user = synchronize_user_for_token( $body['access_token'] );

	return $local_user;
}

/**
 * Get the authorize URL to be used as the redirect_uri in the oauth2 flow.
 */
function get_authorize_url() : string {
	$authorise_url = HM_DELEGATED_AUTH_REST_BASE . 'oauth2/authorize';
	$args = [
		'client_id'     => HM_DELEGATED_AUTH_CLIENT_ID,
		'redirect_uri'  => home_url( '/hm-delegated-auth-callback' ),
		'response_type' => 'code',
	];

	if ( is_multisite() ) {
		$args['redirect_uri'] = add_query_arg( 'site', get_current_blog_id(), network_home_url( '/hm-delegated-auth-callback' ) );
	}

	return add_query_arg( urlencode_deep( $args ), $authorise_url );
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
		$is_querying_token = false;
		return $user;
	}
	$local_user = synchronize_user_for_token( $token );
	$is_querying_token = false;

	if ( is_wp_error( $local_user ) ) {
		wp_die( $local_user );
	}

	return $local_user->ID;
}
