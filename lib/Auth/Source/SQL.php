<?php

/**
 * Simple SQL authentication source
 *
 * This class is an example authentication source which authenticates an user
 * against a SQL database.
 *
 * @package simpleSAMLphp
 */

class sspmod_symfony_Auth_Source_SQL extends sspmod_core_Auth_UserPassBase {


	/**
	 * The DSN we should connect to.
	 */
	private $dsn;


	/**
	 * The username we should connect to the database with.
	 */
	private $username;


	/**
	 * The password we should connect to the database with.
	 */
	private $password;


	/**
	 * Table name where the users are stored.
	 */
	private $table_user_name;

	/**
	* The password encoder
	*/
	private $encoder;


	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info  Information about this authentication source.
	 * @param array $config  Configuration.
	 */
	public function __construct($info, $config) {
		assert('is_array($info)');
		assert('is_array($config)');

		/* Call the parent constructor first, as required by the interface. */
		parent::__construct($info, $config);

		/* Make sure that all required parameters are present. */
		foreach (array('dsn', 'username', 'password', 'table_user_name', 'hash') as $param) {
			if (!array_key_exists($param, $config)) {
				throw new Exception('Missing required attribute \'' . $param .
					'\' for authentication source ' . $this->authId);
			}

			if (!is_string($config[$param])) {
				throw new Exception('Expected parameter \'' . $param .
					'\' for authentication source ' . $this->authId .
					' to be a string. Instead it was: ' .
					var_export($config[$param], TRUE));
			}
		}

		$this->dsn = $config['dsn'];
		$this->username = $config['username'];
		$this->password = $config['password'];
		$this->table_user_name = $config['table_user_name'];
		$this->encoder = new Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder($config['hash']);

	}


	/**
	 * Create a database connection.
	 *
	 * @return PDO  The database connection.
	 */
	private function connect() {
		try {
			$db = new PDO($this->dsn, $this->username, $this->password);
		} catch (PDOException $e) {
			throw new Exception('sqlauth:' . $this->authId . ': - Failed to connect to \'' .
				$this->dsn . '\': '. $e->getMessage());
		}

		$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);


		$driver = explode(':', $this->dsn, 2);
		$driver = strtolower($driver[0]);

		/* Driver specific initialization. */
		switch ($driver) {
		case 'mysql':
			/* Use UTF-8. */
			$db->exec("SET NAMES 'utf8'");
			break;
		case 'pgsql':
			/* Use UTF-8. */
			$db->exec("SET NAMES 'UTF8'");
			break;
		}

		return $db;
	}


	/**
	 * Attempt to log in using the given username and password.
	 *
	 * On a successful login, this function should return the users attributes. On failure,
	 * it should throw an exception. If the error was caused by the user entering the wrong
	 * username or password, a SimpleSAML_Error_Error('WRONGUSERPASS') should be thrown.
	 *
	 * Note that both the username and the password are UTF-8 encoded.
	 *
	 * @param string $username  The username the user wrote.
	 * @param string $password  The password the user wrote.
	 * @return array  Associative array with the users attributes.
	 */
	protected function login($username, $password) {
		assert('is_string($username)');
		assert('is_string($password)');

		$db = $this->connect();

		$test = sprintf("SELECT * FROM `%s` WHERE `username` = :username", $this->table_user_name);

		try {
			$sth = $db->prepare(sprintf("SELECT * FROM `%s` WHERE `username` = :username", $this->table_user_name));
		} catch (PDOException $e) {
			throw new Exception('symfony:' . $this->authId .
				': - Failed to prepare query: ' . $e->getMessage());
		}

		try {
			$res = $sth->execute(array('username' => $username));
		} catch (PDOException $e) {
			throw new Exception('symfony:' . $this->authId .
				': - Failed to execute query: ' . $e->getMessage());
		}

		try {
			$data = $sth->fetch(PDO::FETCH_ASSOC);
		} catch (PDOException $e) {
			throw new Exception('symfony:' . $this->authId .
				': - Failed to fetch result set: ' . $e->getMessage());
		}

		SimpleSAML_Logger::info('symfony:' . $this->authId . ': Got ' . count($data) .
			' rows from database');

		if (!$data) {
			/* No rows returned - invalid username. */
			SimpleSAML_Logger::error('symfony:' . $this->authId .
				': No rows in result set. Probably wrong username/password.');
			throw new SimpleSAML_Error_Error('WRONGUSERPASS');
		}


		//Check password
		foreach (array('password', 'salt') as $param) {
			if (!array_key_exists($param, $data)) {
				throw new Exception('Missing field on table '. $this->table_user_name .' \'' . $param .
					'\' for password resolution ' . $this->authId);
			}
		}

		if (!$this->encoder->isPasswordValid($data['password'], $password, $data['salt'])) {
			/* No rows returned - invalid password. */
			SimpleSAML_Logger::error('symfony:' . $this->authId .
				': No rows in result set. Probably wrong username/password.');
			throw new SimpleSAML_Error_Error('WRONGUSERPASS');
		}

		/* Extract attributes. We allow the resultset to consist of multiple rows. Attributes
		 * which are present in more than one row will become multivalued. NULL values and
		 * duplicate values will be skipped. All values will be converted to strings.
		 */
		$attributes = array();

		foreach ($data as $name => $value) {

			if ($value === NULL) {
				continue;
			}

			$value = (string)$value;

			if (!array_key_exists($name, $attributes)) {
				$attributes[$name] = array();
			}

			if (in_array($value, $attributes[$name], TRUE)) {
				/* Value already exists in attribute. */
				continue;
			}

			$attributes[$name][] = $value;
		}


		SimpleSAML_Logger::info('symfony:' . $this->authId . ': Attributes: ' .
			implode(',', array_keys($attributes)));

		return $attributes;
	}

}
