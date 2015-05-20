# simplesamlphp-module-symfony
Forked from https://github.com/jbdelhommeau/simplesamlphp-module-symfony

Install with composer in your simplesamlphp directory

composer require "philrennie/simplesamlphp-module-symfony:~1.0"

Create an auth source configuration in config.php changing example values as needed.
You might want to check the security.yml in your symfony install to cofirm the hashing method used.
```
$config = array(
    'symfony' => array(
        'symfony:SQL',
        'dsn'=>'mysql:host=localhost;dbname=example',
        'username' =>'example',
        'password' =>'example',
        'table_user_name' =>'ExampleUser',
        'hash'=>'sha512'
    )
);
```
Update your config in saml20-idp-hosted.php to use the auth source. The following is just an example
```
<?php
/**
 * SAML 2.0 IdP configuration for simpleSAMLphp.
 *
 * See: https://simplesamlphp.org/docs/stable/simplesamlphp-reference-idp-hosted
 */

$metadata['__DYNAMIC:1__'] = array(
	/*
	 * The hostname of the server (VHOST) that will use this SAML entity.
	 *
	 * Can be '__DEFAULT__', to use this entry by default.
	 */
	'host' => '__DEFAULT__',

	/* X.509 key and certificate. Relative to the cert directory. */
	'privatekey' => 'example.pem',
	'certificate' => 'example.crt',

	/*
	 * Authentication source to use. Must be one that is configured in
	 * 'config/authsources.php'.
	 */
	'auth' => 'symfony',

	/* Uncomment the following to use the uri NameFormat on attributes. */
	'attributes.NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
  'NameIDFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
);
```
