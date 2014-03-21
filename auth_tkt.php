<?php

/*
 * auth_tkt cookie plugin
 *
 * This plugin generates a mod_auth_tkt cookie when the user logs in, and clears
 * it when they log out. This allows Apache authenticate users to other systems
 * by merit of their Roundcube login in a simple SSO manner.
 *
 * It also redirects to the 'back' URL that mod_auth_tkt provides, if present.
 *
 * See https://github.com/gavincarr/mod_auth_tkt for more about mod_auth_tkt
 *
 * @version 0.1.0
 * @author Jon Stuart
 * @url https://github.com/zomo/roundcube-auth_tkt
 */

class auth_tkt extends rcube_plugin {

  function init() {
    $this->add_hook('login_after', array($this, 'set_cookie'));
    $this->add_hook('session_destroy', array($this, 'unset_cookie'));
    $this->load_config();
  }

  function set_cookie($query) {
    $rcmail = rcmail::get_instance();
    $user = $rcmail->user;

    $key    = $rcmail->config->get('auth_tkt_secret_key');
    $back   = $rcmail->config->get('auth_tkt_back_arg');
    $tokens = $rcmail->config->get('auth_tkt_tokens');
    $data   = $rcmail->config->get('auth_tkt_data');
    $ip     = $_SERVER['REMOTE_ADDR'];

    $hash = $this->getTKTHash($ip, $user->data['username'], $tokens, $data, $key);
    rcube_utils::setcookie('auth_tkt', $hash, 0);

    if (!empty($back) && !empty($query[$back])) {
      $to = $query[$back];
      header('Location: ' . $to);
      exit;
    }
  }

  function unset_cookie() {
    rcube_utils::setcookie('auth_tkt', '-gone-', time() - 60);
  }

  // following function adapted from
  // https://github.com/gavincarr/mod_auth_tkt/blob/master/contrib/auth_ticket.inc.php
  // written by Luc Germain, STI, Universite de Sherbrooke
  // re-used per https://github.com/gavincarr/mod_auth_tkt/blob/master/LICENSE
  function getTKTHash( $ip, $user, $tokens, $data, $key, $base64 = false, $ts = "" ) {

      // set the timestamp to now
      // unless a time is specified
      if( $ts == "" ) {
          $ts = time();
      }
      $ipts = pack( "NN", ip2long($ip), $ts );

      // make the cookie signature
      $digest0 = md5( $ipts . $key . $user . "\0" . $tokens . "\0" . $data );
      $digest = md5( $digest0 . $key );

      if( $tokens ){
          $tkt = sprintf( "%s%08x%s!%s!%s", $digest, $ts, $user, $tokens, $data);
      } else {
          $tkt = sprintf( "%s%08x%s!%s", $digest, $ts, $user, $data);
      }
      if( $base64 ) {
          return( base64_encode( $tkt ) );
      } else {
          return( $tkt );
      }
  }
}

?>
