<?php
// when using secure = true and you are using a self signed cert, export said cert and place it under /etc/ssl/certs
// then check /etc/ldap/ldap.conf

function authLdap($server, $port, $secure, $path ,$timeoutInSec, $username, $password,$debug){
	set_error_handler(function($errno, $errstr, $errfile, $errline, array $errcontext) {
	    // error was suppressed with the @-operator
	    if (0 === error_reporting()) {
	        return false;
	    }

	    throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
	});

	$username = ldap_escape($username, null, LDAP_ESCAPE_DN);
	$password = ldap_escape($password, null, LDAP_ESCAPE_DN);

	$path = str_replace("%username%", $username, $path,$done);
	if($done<1){
		die("Could not replace %username% in path.");
	}

	try{
		if($con = ldap_connect($server, $port)){
			if(!ldap_set_option($con, LDAP_OPT_PROTOCOL_VERSION, 3)) {
				return NULL;
			}
			
			ldap_set_option($con, LDAP_OPT_NETWORK_TIMEOUT, $timeoutInSec);

			if($secure){
				ldap_start_tls($con);
			}

			$bind_return = ldap_bind($con,$path,$password);

			return true;

 			// Depending on your ldap you might want to check if the user account is disabled or not
 			//$filter="(|(sn=*))"; 
 			//$justthese = array( "useraccountcontrol"); 
 			//$sr=ldap_search($con, $path, $filter, $justthese); 
			//$info = ldap_get_entries($con, $sr); 
			//$acctDisabled = (bool)($info->userAccountControl & 0x2);  

		}
	}catch (Exception $e){
		$ldap_error_code=ldap_errno($con);
		$ldap_error_name=ldap_error($con);
		if($debug){
			echo($ldap_error_name." (".$ldap_error_code.") -> ".$e->getMessage());
		}
		return false;
	}
	return false;
}

if(isset($_POST['username']) && isset($_POST['password'])){
	$res = authLdap("172.***.***.***",389,true,"uid=%username%,cn=users,dc=*******,dc=*****,dc=ch",2,$_POST['username'],$_POST['password'],true);
	echo("<br>");
	if($res){
		echo("OK");
	}else{
		echo("NOK");
	}
}else{ ?>
    <form action="#" method="POST">
        <label for="username">Username: </label><input id="username" type="text" name="username" />
        <label for="password">Password: </label><input id="password" type="password" name="password" />
	<input type="submit" name="submit" value="Submit" />
    </form>
<?php } ?>
