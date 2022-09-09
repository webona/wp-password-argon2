<?php
/**
 * Plugin Name: WP Password Argon
 * Plugin URI:  https://webona.agency
 * Description: Replaces wp_hash_password and wp_check_password with PHP 7.2 password functions using Argon2.
 * Author:      Webona s.r.o.
 * Author URI:  https://webona.agency
 * Version:     1.0
 * Licence:     MIT
 */

const PASSWORD_ALGO = PASSWORD_ARGON2I; // PASSWORD_ARGON2ID

/**
 * @param $password
 * @param $hash
 * @param string $userId
 * @return mixed|void
 */
function wp_check_password($password, $hash, $userId = '')
{
	require_once ABSPATH . WPINC . '/class-phpass.php';
	$wp_hasher = new PasswordHash(8, true);

	$check = $wp_hasher->CheckPassword($password, $hash);

	if ( ! $check) {
		return apply_filters('check_password', $check, $password, $hash, $userId);
	}

	$options = apply_filters('wp_hash_password_options', []);

	if (password_needs_rehash($hash, PASSWORD_ALGO, $options)) {
		$hash = wp_set_password($password, $userId);
	}

	$check = password_verify($password, $hash);

	return apply_filters('check_password', $check, $password, $hash, $userId);
}

/**
 * @param $password
 * @return false|string|null
 */
function wp_hash_password($password)
{
	$options = apply_filters('wp_hash_password_options', []);

	return password_hash($password, PASSWORD_ALGO, $options);
}

/**
 * @param $password
 * @param $userId
 * @return false|string|null
 */
function wp_set_password($password, $userId)
{
	/** @var \wpdb $wpdb */
	global $wpdb;

	$hash = wp_hash_password($password);

	$wpdb->update($wpdb->users, ['user_pass' => $hash, 'user_activation_key' => ''], ['ID' => $userId]);

	wp_cache_delete($userId, 'users');

	return $hash;
}
