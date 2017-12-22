<?php

/**
 * Plugin Name: Delegated OAuth 2 Authentication
 * Description: Delegate authentication to another OAuth 2 WordPres site.
 * Author: Joe Hoyle
 */

namespace HM\Delegated_OAuth2;

require_once __DIR__ . '/inc/namespace.php';

if ( ! defined( 'HM_DELEGATED_OAUTH2_REST_BASE' ) ) {
	return;
}
add_filter( 'determine_current_user', __NAMESPACE__ . '\\attempt_authentication', 11 );
add_filter( 'rest_authentication_errors', __NAMESPACE__ . '\\maybe_report_errors' );


