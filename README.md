# Delegated Auth

Delegate authentication and user management to another WordPress site. Support native WordPress logins via the login form, and OAuth2 REST API requests. The AOuth2 REST API plugin must be enabled on the delegated upstream site.

When a login request is delegated to the upstream WordPress site a local cache of the user will be inserted into the WordPress database, mirroring all data, roles and capabilities. The login is synchronized on every request with the upstream WordPress site to make sure data is fresh and capabilities have not been removed. This can add some performance lag on all authenticated requests.
