<?php

/**
 * Plugin Name: Delegated Authentication
 * Description: Delegate authentication to another OAuth 2 WordPress site.
 * Author: Joe Hoyle
 * Version: 1.0.0
 */
namespace HM\Delegated_Auth;

require_once __DIR__ . '/inc/namespace.php';
require_once __DIR__ . '/inc/oauth2/namespace.php';
require_once __DIR__ . '/inc/cookie/namespace.php';

if ( ! defined( 'HM_DELEGATED_AUTH_REST_BASE' ) ) {
	return;
}

add_filter( 'determine_current_user', __NAMESPACE__ . '\\OAuth2\\attempt_authentication', 11 );
add_filter( 'rest_authentication_errors', __NAMESPACE__ . '\\OAuth2\\maybe_report_errors' );

if ( Cookie\is_enabled() ) {
	add_filter( 'determine_current_user', __NAMESPACE__ . '\\Cookie\\attempt_authentication', 11 );
	add_action( 'login_form', __NAMESPACE__ . '\\Cookie\\on_login_form' );
	add_action( 'init', __NAMESPACE__ . '\\Cookie\\on_load' );
}
