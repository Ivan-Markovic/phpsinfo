<?php

/**
 * @version 11/9/2006 7:16PM
 * @file phpsinfo
 * @copyright � 2006 Security-Net.biz
 * @author Ivan Markovic <ivanm@security-net.biz>
 */

class php_si {
    
    var $color  = '';  // security level
    
    // stampanje
    function render() {
        
        $table_up = '<html>
                      <head><title>PHP Security Info</title></head>
                      <body>
                        <table width="50%" border="1" align="center" cellpadding="0" cellspacing="0" bordercolor="#FFFFFF">
                        <tr>
                         <td width="25%" bgcolor="#6666CC"><p><strong>PHP Security Info <br /> <a href="http://www.security-net.biz">Security-Net.biz</a></strong>
                         </td>
                         <td width="75%" bgcolor="#6666CC"><div align="right"><a href="http://www.php.net"><img src="http://static.php.net/www.php.net/images/php.gif" alt="phplogo" name="phplogo" width="120" height="67" border="0" id="phplogo" /></a></div></td>
                        </tr>
                        <tr>
                         <td colspan="2">&nbsp;</td>          
                        </tr>
                        <tr>
                         <td bgcolor="#6666CC"><div align="center"><strong>Test</strong></div></td>
                         <td bgcolor="#6666CC"><div align="center"><strong>Info</strong></div></td>
                        </tr>';
                        
        $table_down = '</table></body></html>';
        
        $table_mid = $this->test();
        
        return $table_up.$table_mid.$table_down;
        
    }
    
    // pred buffer
    function pbuffer($n,$m,$c) {
        
        switch($c) {
            case "red":
                $c = 'FF0000';
                break;
            case "yelow":
                $c = 'FFCC00';
                break;
            case "green":
                $c = '7FDF00';
                break;
            case "blue": // For developing
                $c = '0066FF';    
                break;
        }
        
        $pb .= '<tr>
                <td width="25%" bgcolor="#CCCCFF"><strong>'.$n.'</strong></td>
                <td width="75%" bgcolor="#'.$c.'">'.$m.'</td>
               </tr>';
               
        return $pb;
        
    }
    
    // ini konfiguracija test
    function get_ini($ini_val) {

        $result = ini_get($ini_val);
        
        switch($ini_val) {
         
         //# allow_url_fopen
         case "allow_url_fopen":
            if($result == 1){
                $result = 'Opcija je ukljucena. Ovo je potencijalni sigurnosni propust jer omogucava 
                           umetanje (include) remote fajlova kao da su na vasem serveru.';
                $this->color = 'red';
            } else {
                $result = 'Opcija je iskljucena, ovo je preporuceno podesavanje.';
                $this->color =  'yelow';
            }
         break;
         
         //# display_errors
         case "display_errors":
            if($result == 1){
                $result = 'Opcija je ukljucena. Iskljucite ovu opciju ili u suprotnom ostavljate 
                           mogucnost otkrivanja vitalnih informacija o vasem sistemu.';
                $this->color = 'yelow';
            } else {
                $result = 'Opcija je iskljucena , ovo je preporuceno podesavanje.';
                $this->color =  'green';
            }
         break;  
         
         //# expose_php
         case "expose_php":
            if($result == 1){
                $result = 'Opcija je ukljucena. Ova opcija dodaje PHP potpis na WEB Server Baner i
                           samim tim olaksava potragu potencijalnom napadacu za ranjivostima doticne verzije PHP-a.';
                $this->color = 'yelow';
            } else {
                $result = 'Opcija je ukljucena. , ovo je preporuceno podesavanje.';
                $this->color =  'green';
            }
         break;
         
         //# file_uploads
         case "file_uploads":
            if($result == 1){
                $result = 'Opcija je ukljucena. Ukoliko Vam nije potrebna ova opcija iskljucite je.';
                $this->color = 'yelow';
            } else {
                $result = 'Opcija je ukljucena. Ovo je preporuceno podesavanje ukoliko Vam ova opcija nije potrebna.';
                $this->color =  'green';
            }
         break;  
         
         //# magic_quotes_gpc
         case "magic_quotes_gpc":
            if($result == 1){
                $result = 'Opcija je ukljucena. Ovo je nedovoljan nacin zastite, iskljucite opciju i implementirajte
                           sopstveni system zastite.';
                $this->color = 'red';
            } else {
                $result = 'Opcija je iskljucena , ovo je preporuceno podesavanje.';
                $this->color =  'green';
            }
         break;
         
         //# memory_limit
         case "memory_limit":
         
         define ('NORMAL_MEMORY_LIMIT', 8*1024*1024);
         
            if($result == ""){
                $result = 'Opcija nije ukljucena. Ovim putem ostavljate server nezasticenim na napade koji
                           se zasnivaju na trosenju sistemskih resursa.';
                $this->color = 'red';
            } else if ($this->returnBytes($result) > NORMAL_MEMORY_LIMIT) {
                $result = 'Opcija je postavljena na relativno visoku vrednost. Ukoliko postoji mogucnost
                           postavite ovu vrednost na neku optimalnu (npr: 8MB), u suprotnom ostavljate server 
                           nezasticenim na napade koji se zasnivaju na trosenju sistemskih resursa.';
                $this->color =  'yelow';
            } else {
                $result = 'Opcija je ukljucena, i postavljena na optimalnu vrednost.';
                $this->color =  'green';
            }
         break;   
         
         //# open_basedir
         case "open_basedir":
            if($result == 1){
                $result = 'Opcija je ukljucena, ovo je preporuceno podesavanje.';
                $this->color = 'green';
            } else {
                $result = 'Opcija je iskljucena. Ovim putem dozvoljavate PHP scriptovima pristup 
                           svim lokacijama na vasem serveru.';
                $this->color =  'yelow';
            }
         break;
         
         //# post_max_size
         case "post_max_size":
         
         define ('NORMAL_POST_MAXLIMIT', 1024*256);
         
            if($this->returnBytes($result) > NORMAL_MEMORY_LIMIT || $result = ""){
                $result = 'Opcija je iskljucena, ili je postavljena na veliku vrednost. 
                Ovim putem postajete ranjiviji na potencijalne Denial-Of-Service napade.';
                $this->color = 'yelow';
            } else {
                $result = 'Opcija je ukljucena, i postavljena je na optimalnu vrednost.';
                $this->color =  'green';
            }
         break;
         
         //# register_globals
         case "register_globals":
            if($result == 1){
                $result = 'Opcija je ukljucena. Ovo je ozbiljan sigurnosni propust, iskljuite ovu opciju.';
                $this->color = 'red';
            } else {
                $result = 'Opcija je iskljucena , ovo je preporuceno podesavanje.';
                $this->color =  'green';
            }
         break;
         
         //# upload_max_filesize
         case "upload_max_filesize":
         
            define ('NORMAL_UPLOAD_MAXLIMIT', 1024*256);

            if($this->returnBytes($result) < NORMAL_UPLOAD_MAXLIMIT && $result != -1) { 
                $result = 'Opcija je ukljucena, i postavljena je na optimalnu vrednost.';
                $this->color = 'green';
            } else {
                $result = 'Opcija je iskljucena, ili je postavljena na veliku vrednost. 
                           Ovim putem postajete ranjivi na napade koji se zasnivaju na trosenju sistemskih resursa.';
                $this->color =  'yelow';
            }
         break;                      
         
         //# upload_tmp_dir
         case "upload_tmp_dir":
         
            if( $result === FALSE || $result == '/tmp' || $result == '/temp' ) { 
                $result = 'Opcija je iskljucena, ili je postavljena na uobicajnu rec. Ovim putem omogucavate drugim 
                           korisnicima, na istom serveru, da pristupe privremenim fajlovima drugih korisnika.
                           Uvek postavite ime foldera na neko koje manje asocira na isti.';
                $this->color = 'yelow';
            } else {
                $result = 'Opcija je ukljucena, ovo je preporuceno podesavanje. 
                           Uvek postavite ime foldera na neko koje manje asocira na isti.';
                $this->color =  'green';
            }
         break;
         
         //# use_trans_sid
         case "use_trans_sid":
            if($result == 1) { 
                $result = 'Opcija je ukljucena. Ovim je "session hijacking" mnogo lakse izvesti. 
                           Iskljucite ovu opciju.';
                $this->color = 'red';
            } else {
                $result = 'Opcija je iskljucena , ovo je preporuceno podesavanje.';
                $this->color =  'green';
            }
         break;                 
            
        }
        
        return $result;
        
    }
    
    // testovi
    function test() {
        
    $pbuffer = ''; // pred bafer
         
         $testsfini = array(
                "allow_url_fopen",
                "display_errors",
                "expose_php",
                "file_uploads",
                "magic_quotes_gpc",
                "memory_limit",
                "open_basedir",
                "post_max_size",
                "register_globals",
                "upload_max_filesize",
                "upload_tmp_dir",
                "use_trans_sid",
        );     
        
        foreach ($testsfini as $key => $val) {
            $pbuffer .= $this->pbuffer($val,$this->get_ini($val),$this->color);
        }
        
        return $pbuffer;   
    
    }
    
	// memory value return bytes 
	// preuzeto sa http://us3.php.net/manual/en/function.ini-get.php
	function returnBytes($val) {
	   $val = trim($val);
	   $last = strtolower($val{strlen($val)-1});
	   switch($last) {
	       // The 'G' modifier is available since PHP 5.1.0
	       case 'g':
	           $val *= 1024;
	       case 'm':
	           $val *= 1024;
	       case 'k':
	           $val *= 1024;
	   }
	
	   return $val;
	}
    
}

// Kreiramo objekat
$SEC = new php_si();
echo $SEC->render();

?>
