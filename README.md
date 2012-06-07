# CodeIgniter OAuth 2.0 server for MongoDB

This is an implementation of an OAuth 2.0 (draft 23) authorisation server using the CodeIgniter PHP framework.

## Supported features

* Flows
	* Authorisation code
* Auto approve applications
* Users can manage OAuth permissions


## How to use

1. Put the Oauth controller in your controllers directory
2. Put you Oauth_server library in your libraries directory
3. Set up the database connection in the mongodb config file
4. Create some scopes in the __scopes__ database document (look at the sql file for the fields). Scopes are permissions to access different datasets. For example if you have an API method that exposes a user's details you may have a scope of `user.details`, and if you want clients to be able to update the user's details you could have an additional scope of `user.update`.
5. Create an application in the _applications_ document (look at the sql file for the fields). You may want to extend it and create a controller to allow users to register applications.
6. In the oauth_server library, rewrite the `validate_user()` function code to allow users to sign in. The function should return a user as an object if the username and password are valid or FALSE if not.
7. In your API controller, for each function that requires OAuth authenticated access enter the following code:

```php  
	function user_get($id)
	{
		$this->load->library('oauth_resource_server');
		if ( ! $this->oauth_resource_server->has_scope(array('user.details', 'another.scope')))
		{
			// Error logic here - "access token does not have correct permission to user this API method"
		}
	
		// API code here
	}
```

If an access token successfully validates then you can use the following methods to convert the access token to a user ID:

```php
	$this->oauth_resource_server->is_user();
	// returns the user's ID or FALSE
```

Or to convert the access token to an application ID (if you allow anonomous access tokens):

```php
	$this->oauth_resource_server->is_anon();
	// returns the application ID or FALSE
```

