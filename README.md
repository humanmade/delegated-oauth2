# Delegated Auth

Delegate authentication and user management to another WordPress site. Support native WordPress logins via the login form, and OAuth 2 REST API requests. The OAuth 2 REST API plugin must be enabled on the delegated upstream site.

When a login request is delegated to the upstream WordPress site a local cache of the user will be inserted into the WordPress database, mirroring all data, roles and capabilities. The login is synchronized on every request with the upstream WordPress site to make sure data is fresh and capabilities have not been removed. This can add some performance lag on all authenticated requests.

## Configuring Cookie Auth

For Cookie auth to work correctly you must create an OAuth 2 application on the upstream WordPress site. Do so using the `home_url( '/hm-delegated-auth-callback' )` as the Callback URL, and configure this plugin with the Client ID in the PHP constant `HM_DELEGATED_AUTH_CLIENT_ID`.

Note that if you are using multisite, this must use the home URL for the main site so that the callback URL is the same for the whole network. Delegated Auth then redirects internally between sites as necessary.
