<?php
//find file
date_default_timezone_set("Asia/Kolkata");
ini_set("default_socket_timeout", 600);
//turn off errors for non-local servers
if (strpos($_SERVER['HTTP_HOST'], '.test') === false) error_reporting(0);

if (isset($_SERVER['HTTP_ORIGIN'])) header("Access-Control-Allow-Origin: ".$_SERVER['HTTP_ORIGIN']);
else header('Access-Control-Allow-Origin: *');
function logFetch($data) {
    //log data for local server only
    if (strpos($_SERVER['HTTP_HOST'], '.test')) file_put_contents("../ufs_log.csv", PHP_EOL.date("Y-m-d H:i:s,").'"'.substr($data, 42).'"', FILE_APPEND);
}
function userLogin($user, $pass) {
    loadLogin:
    //get session id first
    $opts = [
        "http" => [
            "method" => "GET",
            "header" => "Accept-language: en\r\n" .
            "User-Agent: ".$_SERVER['HTTP_USER_AGENT']."\r\n"
        ]
    ];
    $context = stream_context_create($opts);
    logFetch("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/login.php");
    $loginPage = @file_get_contents("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/login.php", false, $context);
    if (strlen($loginPage) < 100) goto loadLogin;
    preg_match('/name="csrf" value="([^"]+)/', $loginPage, $matches);
    $csrf = $matches[1];
    preg_match_all("/placeholder=.([^'\"]+)/", $loginPage, $matches);
    $math = explode(" ", $matches[1][2]);
    switch ($math[1]) {
        case '-': $math = $math[0] - $math[2]; break;
        case '+': $math = $math[0] + $math[2]; break;
        case '/': $math = $math[0] / $math[2]; break;
        case '*': $math = $math[0] * $math[2]; break;
    }
    while (strpos($loginPage, 'password')) $loginPage = substr($loginPage, strpos($loginPage, 'password')+1);
    $loginPage = strstr($loginPage, '=');
    $loginPage = strstr($loginPage, ';', true);
    $loginPage = trim(substr($loginPage, 1));
    $loginPage = explode('+', $loginPage);
    $password = '';
    foreach ($loginPage as $part) {
        if ($part[0] == '"' || $part[0] == "'") $password .= trim($part, '"\'');
        else $password .= md5($pass);
    }
    $cookies = array();
    foreach ($http_response_header as $hdr) {
        if (preg_match('/^Set-Cookie:\s*([^;]+)/', $hdr, $matches)) {
            parse_str($matches[1], $tmp);
            $cookies += $tmp;
        }
    }
    //now request for log in using credentials
    
    $postdata = http_build_query(
        array(
            'csrf' => $csrf,
            'username' => $user,
            'password' => $password,
            'answer' => $math
        )
    );
    $opts = [
        "http" => [
            "method" => "POST",
            "header" => "Accept-language: en\r\n" .
                "User-Agent: ".$_SERVER['HTTP_USER_AGENT']."\r\n".
                "Cookie: ".str_replace(", ", ";", http_build_query($cookies))."\r\n".
                "Origin: https://bhuvan-rsa1.nrsc.gov.in\r\n".
                "Referer: https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/login.php\r\n".
                "Content-Type: application/x-www-form-urlencoded\r\n",
            'content' => $postdata
        ]
    ];
    $context = stream_context_create($opts);
    logFetch("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/login_register.php");
    $jsoPage = @file_get_contents("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/login_register.php", false, $context);
    if (strpos($jsoPage, 'Unauthorized Access')) return false;
    else if (stripos($jsoPage, 'Your account is locked')) return null;
    else if (strpos($jsoPage, 'Your account is not activated at the Moment. Please contact your reporting officer')) return 0;
    else return $cookies;
}
function fetchData($url, $referer, $cookie) {
    $retryCount = -1;
    $returnCookie = false;
retryFetch:
    $opts = [
        "http" => [
            "method" => "GET",
            "header" => "Accept-language: en\r\n" .
            "User-Agent: ".$_SERVER['HTTP_USER_AGENT']."\r\n".
            "Cookie: ".str_replace(", ", ";", http_build_query($cookie))."\r\n".
            "Origin: https://bhuvan-rsa1.nrsc.gov.in\r\n".
            "Referer: $referer\r\n"
        ]
    ];
    $context = stream_context_create($opts);
    logFetch($url);
    $listPage = @file_get_contents($url, false, $context);
    //get status code
    $parts=explode(' ',@$http_response_header[0]);
    if (strpos($listPage, 'Unauthorized Access')) {
    retryLogin4Fetch:
        $login = userLogin($_POST['userid'], $_POST['password']);
        $retryCount++;
        if (!$login) {
            if ($retryCount < 3) goto retryLogin4Fetch;
            else return [null, null];
        }
        //send these new cookies to response
        $cookie = $login;
        $returnCookie = true;
        //fetch requested page again
        goto retryFetch;
    }
    else if (count($parts)>1 && $parts[1]>299) { //only response code 2xx is valid
        $retryCount++;
        if ($retryCount < 5) goto retryFetch;
        else return [null, null];
    }
    return [$listPage, ($returnCookie?$cookie:null)];
}
//Begin handling POST Data
if (!isset($_POST['method']) || !isset($_POST['userid']) || !isset($_POST['password']) || $_POST['password'] == '') die();
header('Content-Type: application/json');
$userid = $_POST['userid'];
$password = $_POST['password'];
if (isset($_POST['targetCookie'])) $cookies = json_decode($_POST['targetCookie'], true);
else $cookies = [];
switch ($_POST['method']) {
    case 'login':
        if (!preg_match("/JSO[1-9]\d?_\d{7}|SSO[1-9]\d?_\d{7}|RH_[A-Z]{3,}|SRO_[A-Z]{3,}|NSRO_[A-Z]{3,}|ZO_[A-Z]{3,}|HQ/", $userid)) die('false');
        $login = userLogin($userid, $password);
        //if no cookies returned, login failed
        if (!is_array($login)) die(json_encode($login));
        else $cookies = $login;
        if ($userid[0] == 'J') {
            //set the cookies for further use
            $retArray = ["userid"=>$userid, "password"=>$password, "usertype"=>'JSO', "targetCookie"=>$cookies];
            list($jsoPage, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/jso.php", "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/nsso.php", $cookies);
            if ($jsoPage == null) die();
            if ($cookie) $cookies = $cookie;
            $data = array();
            $lyr = strstr($jsoPage, "var userid");
            $lyr = explode("\n", $lyr, 6);
            unset($lyr[5]);
            foreach ($lyr as $l) {
                if (strpos($l, '"') === false && strpos($l, "'") === false) continue;
                if (strpos($l, '"') === false) $d = strstr($l, "'");
                else $d = strstr($l, '"');
                $d = substr($d, 1);
                if (strpos($l, '"') === false) $d = strstr($d, "'", true);
                else $d = strstr($d, '"', true);
                if (stripos($l, 'town')) $data['town'] = $d;
                else if (stripos($l, 'district')) $data['district'] = $d;
                else if (stripos($l, 'state')) $data['state'] = $d;
            }
            $jsoPage = strip_tags($jsoPage);
            if (!isset($data['town']) || $data['town'] == '' || !isset($data['district']) || $data['district'] == '' || !isset($data['state']) || $data['state'] == '') {
                die();//don't send any data, as it is possible error
            }
            else $retArray['data'] = $data;
            
            $data = array();
            if (stripos($jsoPage, "No data for  Town") == false) $data[] = "Town";
            if (stripos($jsoPage, "No data for  Ward") == false) $data[] = "Ward";
            if (stripos($jsoPage, "No data for  IV") == false) $data[] = "IV";
            if (stripos($jsoPage, "No data for  Block") == false) $data[] = "Block";
            if (stripos($jsoPage, "No data for  Listing") == false) $data[] = "Listing";
            //skip listing
            $retArray["available"] = $data;
            die(json_encode($retArray));
        }
        else if ($userid[0] == 'S' && $userid[1] == 'S') {
            //set the cookies for further use
            $retArray = ["userid"=>$userid, "password"=>$password, "usertype"=>'SSO', "targetCookie"=>$cookies];
            list($jsoPage, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/sso.php", "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/nsso.php", $cookies);
            if ($jsoPage == null) die();
            if ($cookie) $cookies = $cookie;
            $lyr = strstr($jsoPage, "loadlayer_solar_sso(\"");
            $lyr = strstr($lyr, ")", true);
            $lyr = str_replace("\n", '', $lyr);
            preg_match_all('/"([^"]+)"/', $lyr, $lyr);
            $jsoPage = strstr($jsoPage, '<body');
            $jsoPage = ".".strip_tags($jsoPage);
            $data = [];
            $data['town'] = @$lyr[1][1];
            $data['district'] = @$lyr[1][2];
            $data['state'] = @$lyr[1][3];
            if (strlen(@$lyr[1][0])) $data['jso'] = explode('***', $lyr[1][0]);
            if (!isset($data['town']) || $data['town'] == '' || !isset($data['district']) || $data['district'] == '' || !isset($data['state']) || $data['state'] == '') {
                die();//don't send any data, as it is possible error
            }
            else $retArray['data'] = $data;
            $data = array();
            if (stripos($jsoPage, "No data for  Town") == false) $data[] = "Town";
            if (stripos($jsoPage, "No data for  Ward") == false) $data[] = "Ward";
            if (stripos($jsoPage, "No data for  IV") == false) $data[] = "IV";
            if (stripos($jsoPage, "No data for  Block") == false) $data[] = "Block";
            if (stripos($jsoPage, "No data for  Listing") == false) $data[] = "Listing";
            //skip listing
            $retArray["available"] = $data;
            die(json_encode($retArray));
        }
        else if ($userid[0] == 'S') {
            //sro login
            $retArray = ["userid"=>$userid, "password"=>$password, "usertype"=>'SRO', "targetCookie"=>$cookies, "available"=>null, "data"=>null];
            die(json_encode($retArray));
        }
        else if ($userid[0] == 'N') {
            //nsro login
            $retArray = ["userid"=>$userid, "password"=>$password, "usertype"=>'NSRO', "targetCookie"=>$cookies, "available"=>null, "data"=>null];
            die(json_encode($retArray));
        }
        else if ($userid[0] == 'R') {
            //rh login
            $retArray = ["userid"=>$userid, "password"=>$password, "usertype"=>'RH', "targetCookie"=>$cookies, "available"=>null, "data"=>null];
            die(json_encode($retArray));
        }
        else if ($userid[0] == 'Z') {
            //zo login
            $retArray = ["userid"=>$userid, "password"=>$password, "usertype"=>'ZO', "targetCookie"=>$cookies, "available"=>null, "data"=>null];
            die(json_encode($retArray));
        }
        else if ($userid[0] == 'H') {
            //hq login
            $retArray = ["userid"=>$userid, "password"=>$password, "usertype"=>'HQ', "targetCookie"=>$cookies, "available"=>null, "data"=>null];
            die(json_encode($retArray));
        }
        break;
    case 'fetch':
    case 'export':
        //user is logged in, show him the page that has been requested
        switch(strtolower($userid[0])) {
            case 'j':
                $userType = 'jso';
                break;
            case 's':
                if (strtolower($userid[1]) == 's') $userType = 'sso';
                else $userType = 'sro';
                break;
            case 'r':
                $userType = 'rh';
                break;
            case 'n':
                $userType = 'sro';
                break;
            case 'z':
                $userType = 'zo';
                break;
            case 'h':
                $userType = 'hq';
                break;
            default:
                $userType = '';
                break;
        }
        $profile = $_POST['json'];
        $townid = isset($_POST['town'])?$_POST['town']:0;
        //decide referer
        if ($_POST['method'] == 'export') {
            if ($userType == 'jso') $referer = "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_jso.php?userid=$userid@@@@$profile@@@@https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@$profile@@@@1@@@@10";
            else if ($userType == 'sso') $referer = "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_sso.php?userid=0@@@@$profile@@@@https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@$profile@@@@1@@@@10";
            else $referer = "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_".$userType.".php?userid=$userid@@@@$profile@@@@https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@$profile@@@@$townid@@@@0";
        } else $referer = "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/".$userType.".php";
        //fix page numbers and other params
        $page = (isset($_POST['page']) && is_numeric($_POST['page']) && $_POST['page']>1)?$_POST['page']*1:1;
        $_POST['json'] = strtolower($_POST['json']);
        if(!in_array($_POST['json'], array('townboundary', 'ivunitboundary', 'wardboundary', 'blockboundary', 'listing'))) die('{"ok": false, "start": 0, "end": 0, "total":0, "rows": []}');
        $recordlimit = (isset($_POST['recordlimit']) && is_numeric($_POST['recordlimit']) && $_POST['recordlimit']>10 && $_POST['recordlimit']<100)?$_POST['recordlimit']*1:10;
        if ($_POST['method'] == 'export') {
            if ($userType == 'jso') $url = "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/excel_jso_export.php?userid=$userid&layrname=$profile&tablename=$profile";
            else if ($userType == 'sso') $url = "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/excel_sso_export.php?userid=0@@@@$profile@@@@https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@$profile";
            else $url = "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/excel_".$userType."_export.php?userid=$userid@@@@$profile@@@@=https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@$profile@@@@$townid@@@@0";
        } else {
            if ($userType == 'jso') $url = "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_$userType.php?page=$page&userid=$userid@@@@$profile@@@@https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@$profile@@@@1@@@@10&recordlimit=$recordlimit";
            else if ($userType == 'sso') $url = "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_$userType.php?page=$page&userid=0@@@@$profile@@@@https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@$profile@@@@1@@@@10&recordlimit=$recordlimit";
            else $url = "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_$userType.php?page=$page&userid=$userid@@@@$profile@@@@=https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@$profile@@@@$townid@@@@0&recordlimit=$recordlimit";
        }
        /*
        URLs:
        JSO:
            https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_jso.php?userid=JSO1_0211009@@@@listing@@@@https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@listing@@@@1@@@@10
            (Referer: https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/jso.php)
            https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_jso.php?page=4&userid=JSO1_0211009@@@@listing@@@@https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@listing@@@@1@@@@10&recordlimit=10
        SSO (Select):
            https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_sso.php?userid=0@@@@listing@@@@https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@listing
            (Referer: https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/sso.php)
        SSO (ALL):
            https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_sso.php?page=3&userid=JSO1_0211009***JSO17_0211009***JSO18_0211009***JSO2_0211009***JSO20_0211009***JSO7_0211009***JSO8_0211009@@@@listing@@@@https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@listing&recordlimit=10
        SSO (JSO Selected):
            https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_sso.php?userid=JSO2_0211009%20%20%20%20%20%20%20%20@@@@listing@@@@https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@listing
            (Referer: https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/sso.php)
            https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_sso.php?page=3&userid=JSO2_0211009%20%20%20%20%20%20%20%20@@@@listing@@@@https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@listing&recordlimit=10
        SRO (Select):
            https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_sro.php?page=2&userid=SRO_MANDI@@@@blockboundary@@@@=https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@blockboundary@@@@002***2***4@@@@0&recordlimit=10
            (Referer: https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/sro.php)
            https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_sro.php?userid=SRO_MANDI@@@@blockboundary@@@@=https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@blockboundary@@@@002***2***4@@@@JSO1_0204002
            https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/excel_sro_export.php?userid=SRO_MANDI@@@@blockboundary@@@@=https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@blockboundary@@@@002***2***4@@@@0
        RH (JSO Selected):
            https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_rh.php?userid=RH_SHIMLA@@@@blockboundary@@@@https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@blockboundary@@@@002***2***4@@@@JSO1_0204002
            (Referer: https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/rh.php)
            https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_rh.php?page=2&userid=RH_SHIMLA@@@@blockboundary@@@@https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@blockboundary@@@@002***2***4@@@@JSO1_0204002&recordlimit=10
        SRO Town Data List: https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/sro_town_jso.php?towncode=005***2***5&userid=SRO_MANDI
        RH Town Data List: https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/rh_town_jso.php?towncode=002***2***4&userid=RH_SHIMLA
        Export:
            https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/excel_rh_export.php?userid=RH_SHIMLA@@@@blockboundary@@@@https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@blockboundary@@@@002***2***4@@@@0
        */
        list($listPage, $cookie) = fetchData($url, $referer, $cookies);
        if ($cookie) $cookies = $cookie;
        preg_match('/Showing (\d+) to (\d+) of (\d+) entries/', $listPage, $matches);
        if (count($matches)) {
            $start = $matches[1]*1;
            $end = $matches[2]*1;
            $total = $matches[3]*1;
        } else { $start=$end=$total=0; }
        $listPage = strstr($listPage, '</table>');
        $listPage = strstr($listPage, '<tr');
        $listPage = strstr($listPage, '</table>', true);
        $listPage = preg_replace('/\s+/', ' ', $listPage);
        $listPage = explode('</tr>', $listPage);
        $heads = explode('</th>', $listPage[0]);
        $last = count($heads);
        $allowedColumns =  array('North'=>'North', 'East'=>'East', 'South'=>'South', 'West'=>'West', 'Other Details'=>'Details', 'Details'=>'Details', 'Status'=>'Status', 'Record No'=>'Record', 'Ward No'=>'Ward', 'IV Unit Number'=>'IV', 'Block Number'=>'Block', 'Name of Structure'=>'Building', 'Name of the Owner'=>'Owner', 'Number of Households'=>'Total', 'Landmark'=>'Landmark', 'Corner Point'=>'Corner', 'House Number'=>'House', 'Type of Area 1 (Code)'=>'Area1', 'Type of Area 2 (Code)'=>'Area2', 'Auxilliary Information 1 (Code)'=>'Aux1', 'Auxilliary Information 2 (Code)'=>'Aux2', 'Auxilliary Information 3 (Code)'=>'Aux3', 'Auxilliary Information 4 (Code)'=>'Aux4', 'Auxilliary Information 5 (Code)'=>'Aux5', 'Creation Time'=>'Time', 'Photo 1 Name'=>'Pic1', 'Photo 2 Name'=>'Pic2', 'Photo 3 Name'=>'Pic3', 'Photo 4 Name'=>'Pic4', 'Observer Name'=>'Observer', 'User ID'=>'User', 'User Id'=>'User');
        for ($i=0; $i<$last; $i++) {
            if (!isset($allowedColumns[trim(strip_tags($heads[$i]))])) unset($heads[$i]);
            else $heads[$i] = trim(strip_tags($heads[$i]));
        }
        unset($listPage[0]);
        unset($listPage[count($listPage)]);
        $rows = array();
        foreach ($listPage as $list) {
            $row = array();
            $pics = array();
            $aux = array();
            $list = explode('</td>', $list);
            foreach ($heads as $i=>$t) {
                $d = trim(strip_tags($list[$i]));
                //replace 0 and NA with ''
                $row[$t] = ($d==="0" || strtolower($d) == 'na')?"":$d;
                //replace 0 for household count
                if ($t == 'Number of Households' && $row[$t] == '') $row[$t] = '0';
                //merge images and auxilliary
                else if (in_array($t, array('Photo 1 Name', 'Photo 2 Name', 'Photo 3 Name', 'Photo 4 Name'))) {
                    //process for image
                    preg_match('#//(.+)[\'"]#', $list[$i], $matches);
                    if (count($matches) > 1) $pics[] = $matches[1];
                    unset($row[$t]);
                }
                else if (in_array($t, array('Auxilliary Information 1 (Code)', 'Auxilliary Information 2 (Code)', 'Auxilliary Information 3 (Code)', 'Auxilliary Information 4 (Code)', 'Auxilliary Information 5 (Code)'))) {
                    $aux[] = $row[$t];
                    unset($row[$t]);
                }
            }
            $row['Image'] = $pics;
            //push aux for blocks
            if (isset($row['Block Number']) && !isset($row['Number of Households'])) $row['Aux'] = $aux;
            //apply transformations
            foreach ($allowedColumns as $oldkey=>$newkey) {
                if (!isset($row[$oldkey])) continue;
                $row[$newkey] = $row[$oldkey];
                if ($newkey != $oldkey) unset($row[$oldkey]);
            }
            //don't send User ID for JSO
            if ($userid[0] == 'J') {
                unset($row['Observer']);
                unset($row['User']);
            }
            $rows[] = $row;
        }
        //send cookies if a mismatch is found
        if ($_POST['method'] == 'export') {
            if (json_encode($cookies) != $_POST['targetCookie']) die(json_encode(array("ok"=>true, "total"=>count($rows), "targetCookie"=>$cookies, "rows"=>$rows)));
            else die(json_encode(array("ok"=>true, "total"=>count($rows), "rows"=>$rows)));
        } else {
            if (json_encode($cookies) != $_POST['targetCookie']) die(json_encode(array("ok"=>true, "start"=>$start, "end"=>$end, "total"=>$total, "targetCookie"=>$cookies, "rows"=>$rows)));
            else die(json_encode(array("ok"=>true, "start"=>$start, "end"=>$end, "total"=>$total, "rows"=>$rows)));
        }
        break;
    case 'locate':
        if (!isset($_POST['record_no'])) die();//need all parameters to work
        $recordID = $_POST['record_no'];
        $tableName = isset($_POST['tableName'])?$_POST['tableName']:'listing';
        $ut = strtolower(explode('_', $userid)[0]);
        $ut = preg_replace('/[^a-z]/i', '', $ut);
        if ($ut == 'NSRO') $ut = 'sro';
        list($listPage, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/zoomtorecord.php?record_id=$recordID&tablename=$tableName&wmsname=$tableName&layerurl=https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms", "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/".$ut.".php", $cookies);
        if (strpos($listPage, '>') !== false) $listPage = substr($listPage, strrpos($listPage, '>')+1);
        $listPage = trim($listPage);
        if (strlen($listPage) < 7) $listPage = '0_0_0_0';
        die($listPage);
        break;
    case 'towns':
        if ($userid[0] == 'J' || ($userid[0] == 'S' && $userid[1] == 'S')) die();//JSO and SSO not allowed
        $ut = explode('_', $userid)[0];
        if ($ut == 'NSRO') $ut = 'sro';
        $url = 'https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/'.strtolower($ut).'.php';
        list($listPage, $cookie) = fetchData($url, 'https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/nsso.php', $cookies);
        $listPage = strstr($listPage, 'towndrpdown');
        $listPage = strstr($listPage, '</select>', true);
        //if (!$listPage) die('');
        preg_match_all("/<option\s+value\s*=\s*['\"]([^'\">]+)[^>]*>([^<]+)/", $listPage, $_towns);
        $towns = [];
        //skip 0 and all, then scrape all into towns list
        for ($i = 2; $i < count($_towns[1]); $i++) {
            $towns[] = array('name'=>$_towns[2][$i], 'code'=>$_towns[1][$i]);
        }
        die(json_encode(array('ok'=>true, 'towns'=>$towns)));
        break;
    case 'available':
        if ($userid[0] == 'J' || ($userid[0] == 'S' && $userid[1] == 'S')) die();//JSO and SSO not allowed
        if (!isset($_POST['town'])) die();//need all parameters to work
        $ut = strtolower(explode('_', $userid)[0]);
        if ($ut == 'nsro') $ut = 'sro';
        $url = 'https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/'.$ut.'_town_jso.php?towncode='.$_POST['town'].'&userid='.$userid;
        list($listPage, $cookie) = fetchData($url, "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/".$ut.".php", $cookies);
        if ($cookie) $cookies = $cookie;
        $listPage = strip_tags($listPage);
        $data = array();
        if (stripos($listPage, "No data for  Town") == false) $data[] = "Town";
        if (stripos($listPage, "No data for  Ward") == false) $data[] = "Ward";
        if (stripos($listPage, "No data for  IV") == false) $data[] = "IV";
        if (stripos($listPage, "No data for  Block") == false) $data[] = "Block";
        if (stripos($listPage, "No data for  Listing") == false) $data[] = "Listing";
        $output = array('ok'=>true, 'available'=>$data, 'data'=>null);
        //fetch data - state name, code, district name, code and town name, code
        $url = 'https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/tabular_data_'.$ut.'.php?userid='.$userid.'@@@@blockboundary@@@@=https://bhuvan-rsa1.nrsc.gov.in/bhuvangid/nsso_p2/wms@@@@blockboundary@@@@'.$_POST['town'].'@@@@0';
        list($listPage, $cookie) = fetchData($url, "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/".$ut.".php", $cookies);
        if ($cookie) $cookies = $cookie;
        if (json_encode($cookies) != $_POST['targetCookie']) $output['targetCookie'] = $cookies;
        preg_match('/JSO\d\d?_(\d\d)(\d\d)(\d\d\d)/', $listPage, $matches);
        $data = [];
        $data['statecode'] = $matches[1];
        $data['districtcode'] = $matches[2];
        $data['towncode'] = $matches[3];
        $listPage = strstr($listPage, 'BlockBoundary');
        $listPage = strstr($listPage, '</tr', true);
        $listPage = explode('</td>', $listPage);
        $data['state'] = trim(strip_tags($listPage[1]));
        $data['district'] = trim(strip_tags($listPage[3]));
        $data['town'] = trim(strip_tags($listPage[5]));
        $output['data'] = $data;
        die(json_encode($output));
        break;
    case 'submit':
        if (!($userid[0] == 'J' || $userid[0] == 'R' || ($userid[0] == 'S' && $userid[1] == 'S'))) die();//Only JSO, SSO and RH are allowed
        if (!(isset($_POST['record_no']) && isset($_POST['tableName']))) die();//need all parameters to work
        $recordID = $_POST['record_no'];
        $tableName = $_POST['tableName'];
        $ut = strtolower(explode('_', $userid)[0]);
        $ut = preg_replace('/[^a-z]/i', '', $ut);
        $url = "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/bulk_save_".$ut.".php?record_no=$recordID&tablename=$tableName&action=1&userid=$userid";
        if ($userid[0] == 'J') $url = "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/bulk_town_save_jso.php?record_no=$recordID&tablename=$tableName&action=1";
        list($listPage, $cookie) = fetchData($url, "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/$ut.php", $cookies);
        //no need to check login or if already submitted, simply send the request
        die(trim($listPage));
    case 'reject':
        if (!($userid[0] == 'R' || ($userid[0] == 'S' && $userid[1] == 'S'))) die();//Only SSO and RH are allowed
        if (!(isset($_POST['record_no']) && isset($_POST['tableName']) && isset($_POST['reason']))) die();//need all parameters to work
        $recordID = $_POST['record_no'];
        $tableName = $_POST['tableName'];
        $ut = strtolower(explode('_', $userid)[0]);
        $ut = preg_replace('/[^a-z]/i', '', $ut);
        list($listPage, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/bulk_save_".$ut.".php?record_no=$recordID&tablename=$tableName&userid=$userid&action=2&reason=".urlencode($_POST['reason']), "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/$ut.php", $cookies);
        //no need to check login or if already rejected, simply send the request
        die($listPage);
    case 'update':
        if ($userid[0] != 'J') die();//Only JSO is allowed
        $boundary = str_replace('boundary', '', $_POST['recordtype']);
        foreach ($_POST as $k=>$v) if ($v == '') $_POST[$k] = '0';
        //filter $_POST before pushing all to server
        $push = array();
        $convert = array(''=>'', 'north'=>'North', 'east'=>'East', 'west'=>'West', 'south'=>'South', 'details'=>'Details', 'record_no'=>'Record No', 'ivunitno'=>'IV Unit Number', 'wardno'=>'Ward No', 'blockno'=>'Block Number', 'auxilliary1'=>'Auxilliary Information 1 (Code)', 'auxilliary2'=>'Auxilliary Information 2 (Code)', 'auxilliary3'=>'Auxilliary Information 3 (Code)', 'auxilliary4'=>'Auxilliary Information 4 (Code)', 'auxilliary5'=>'Auxilliary Information 5 (Code)', 'typeofarea1'=>'Type of Area 1 (Code)', 'typeofarea2'=>'Type of Area 2 (Code)', 'housenumber'=>'House Number', 'namestructure'=>'Name of Structure', 'ownername'=>'Name of the Owner', 'noofhousehold'=>'Number of Households', 'landmark'=>'Landmark', 'cornerpoint'=>'Corner Point');
        foreach ($_POST as $k=>$v) if (isset($convert[$k])) $push[$k] = $v==''?'0':$v;
        list($listPage, $cookie) = fetchData('https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/jso_update_attributes_'.$boundary.'.php?'.http_build_query($push), "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/jso.php", $cookies);
        die(trim($listPage));
        break;
    case 'change':
        if ($userid[0] != 'J') die();//Only JSO is allowed
        if (!(isset($_POST['item']) && isset($_POST['new']) && isset($_POST['old']))) die();//need all parameters to work
        if ($_POST['item'] == 'blockno') {
            $url = 'https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/update_jso_block.php?userid='.$userid.'@@@@blockboundary@@@@blockno@@@@'.$_POST['old'].'_'.$_POST['ivunitno'].'_'.$_POST['wardno'].'@@@@'.$_POST['new'].'@@@@'.$_POST['ivunitno'].'@@@@'.$_POST['wardno'];
        } else if ($_POST['item'] == 'wardno') {
            $url = 'https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/update_jso_ward.php?userid='.$userid.'@@@@wardboundary@@@@wardno@@@@'.$_POST['old'].'@@@@'.$_POST['new'];
        } else if ($_POST['item'] == 'ivunitno') {
            $url = 'https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/update_jso_ivunit.php?userid='.$userid.'@@@@ivunitboundary@@@@ivunitno@@@@'.$_POST['old'].'@@@@'.$_POST['new'];
        } else die();
        list($listPage, $cookie) = fetchData($url, 'https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/jso.php', $cookies);
        die(trim($listPage));
        break;
    case 'delete':
        if ($userid[0] != 'J') die();//Only JSO is allowed
        if (!(isset($_POST['record_no']) && isset($_POST['tableName']))) die();//need all parameters to work
        $recordID = $_POST['record_no'];
        $userid = $userid;
        $tableName = $_POST['tableName'];
        list($listPage, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/delete_jso.php?record_id=$recordID&tablename=$tableName&userid=$userid", 'https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/jso.php', $cookies);
        //no need to check login or if already deleted, simply send the request
        die(trim($listPage));
        break;
    case 'resurvey':
        if ($userid[0] != 'R') die();//Only RH is allowed
        if (!(isset($_POST['record_no']) && isset($_POST['tableName']))) die();//need all parameters to work
        $recordID = $_POST['record_no'];
        $tableName = $_POST['tableName'];
        list($listPage, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/bulk_save_rh.php?record_no=$recordID&tablename=$tableName&userid=$userid&action=3", "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/rh.php", $cookies);
        //no need to check login or if already deleted, simply send the request
        die($listPage);
    case 'clearuuid':
        if ($userid[0] != 'R') die();//Only RH is allowed
        if (!(isset($_POST['gid']) || !isset($_POST['tableName']))) die();//need all parameters to work
        list($listPage, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/updateuuid.php?gidno=".$_POST['gid'], "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/clearuuid.php", $cookies);
        die($listPage);
    case 'activate':
        if ($userid[0] != 'R') die();//Only RH is allowed
        if (!isset($_POST['gid'])) die();//need all parameters to work
        list($listPage, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/updateuserstatus.php?gidno=".$_POST['gid'], "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/enablelogin.php", $cookies);
        die($listPage);
    case 'deactivate':
        if ($userid[0] != 'R') die();//Only RH is allowed
        if (!isset($_POST['gid'])) die();//need all parameters to work
        list($listPage, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/deactivateuserstatus.php?gidno=".$_POST['gid'], "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/enablelogin.php", $cookies);
        die($listPage);
    case 'resetpassword':
        if ($userid[0] != 'R') die();//Only RH is allowed
        if (!isset($_POST['gid'])) die();//need all parameters to work
        list($listPage, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/resetpassword.php?gidno=".$_POST['gid'], "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/clearuuid.php", $cookies);
        die($listPage);
    case 'getUsers':
        if ($userid[0] != 'R') die();//Only RH is allowed
        list($data, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/clearuuid.php", "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/nsso.php", $cookies);
        if (!$data) die(json_encode(array("ok"=>false, "reason"=>'Login failed!', "users"=>[], 'raw'=>$raw_data)));
        if ($cookie) $cookies = $cookie;
        $raw_data = $data;
        $data = strstr($data, '<table');
        $data = strstr($data, 'tablestatus');
        $data = strstr($data, '</table', true);
        $data = preg_replace('/\s+/', ' ', $data);
        $uuids = [];
        //scrape table rows from this data
        foreach (explode('tr>', $data) as $row) {
            if (stripos($row, '<thead') || stripos($row, 'Designation')) continue;
            $cells = explode('</td>', $row);
            if (count($cells) < 8) continue;
            if (trim(strip_tags($cells[8])) == '') {
                preg_match('/value\s*=\s*.([^\'"]+)/', $cells[8], $uuid);
                $cells[8] = $uuid[1];
            } else $cells[8] = trim(strip_tags($cells[8]));
            $cell = array('user_id'=>trim(strip_tags($cells[0])), 'district'=>trim(strip_tags($cells[4])), 'town'=>trim(strip_tags($cells[5])), 'gid'=>trim(strip_tags($cells[6]))*1, 'status'=>trim(strip_tags($cells[7])), 'uuid'=>$cells[8]);
            $uuids[] = $cell;
        }
        if (count($uuids)) {
            if ($cookie) die(json_encode(array("ok"=>true, "users"=>$uuids, "targetCookie"=>$cookies)));
            else die(json_encode(array("ok"=>true, "users"=>$uuids)));
        }
        else die(json_encode(array("ok"=>false, "reason"=>'Parsing failed!', "users"=>[], 'raw'=>$raw_data)));
    case 'listsro':
        if ($userid[0] != 'R') die();//Only RH is allowed
        list($data, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/create_user_town_jso.php?statecode=&towncode=&districtcode=", "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/createuser.php", $cookies);
        if ($cookie) $cookies = $cookie;
        if (!$data) die(json_encode(array("ok"=>false, "reason"=>'Login failed!', "sro"=>[], 'raw'=>$raw_data)));
        $raw_data = $data;
        $data = strstr($data, 'rep_sso');
        $data = strstr($data, '</select', true);
        preg_match_all('/<option[^>]+value\s*=\s*.([^\'"]+)[^>]+>([^<]+)/', $data, $opts);
        $sro = [];
        for ($i = 0; $i < count($opts[1]); $i++) {
            $opt = ucwords(strtolower(str_replace('_', ' ', $opts[1][$i])));
            $opt = strtoupper(substr($opt, 0, strpos($opt, ' '))).substr($opt, strpos($opt, ' '));
            if (trim($opt)) $sro[$opts[1][$i]] = $opt;
        }
        if (count($sro)) {
            if ($cookie) die(json_encode(array("ok"=>true, "sro"=>$sro, "targetCookie"=>$cookies)));
            else die(json_encode(array("ok"=>true, "sro"=>$sro)));
        }
        else die(json_encode(array("ok"=>false, "reason"=>'Parsing failed!', "sro"=>[], 'raw'=>$raw_data)));
    case 'listrepo':
        if ($userid[0] != 'R') die();//Only RH is allowed
        if (!(isset($_POST['state']) && isset($_POST['district']) && isset($_POST['town']))) die();//need all parameters to work
        list($data, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/create_user_town_jso.php?statecode=".$_POST['state']."&towncode=".$_POST['town']."&districtcode=".$_POST['district'], "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/createuser.php", $cookies);
        if ($cookie) $cookies = $cookie;
        if (!$data) die(json_encode(array("ok"=>false, "reason"=>'Login failed!', "sro"=>[], 'raw'=>$raw_data)));
        $raw_data = $data;
        $data = substr($data, strrpos($data, '</select'));
        $trs = explode('</tr>', $data);
        $jso = [];
        for ($i = 2; $i < count($trs); $i++) {
            $opts = explode('</td>', $trs[$i], 2);
            if (count($opts) == 2) $jso[trim(strip_tags($opts[0]))] = trim(strip_tags($opts[1]));
        }
        if (count($jso)) {
            if ($cookie) die(json_encode(array("ok"=>true, "jso"=>$jso, "targetCookie"=>$cookies)));
            else die(json_encode(array("ok"=>true, "jso"=>$jso)));
        }
        else die(json_encode(array("ok"=>false, "reason"=>'Parsing failed!', "jso"=>[], 'raw'=>$raw_data)));
    case 'createsso':
        if ($userid[0] != 'R') die();//Only RH is allowed
        if (!(isset($_POST['state']) && isset($_POST['district']) && isset($_POST['town']) && isset($_POST['reporting']))) die();//need all parameters to work
        list($listPage, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/sso_user_name_save.php?statecode=".$_POST['state']."&towncode=".$_POST['town']."&districtcode=".$_POST['district']."&userid=".$userid."&repoid=".$_POST['reporting'], "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/createuser.php", $cookies);
        die($listPage);
    case 'createjso':
        if ($userid[0] != 'R') die();//Only RH is allowed
        if (!(isset($_POST['state']) && isset($_POST['district']) && isset($_POST['town']) && isset($_POST['reporting']))) die();//need all parameters to work
        list($listPage, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/jso_user_name_save.php?statecode=".$_POST['state']."&towncode=".$_POST['town']."&districtcode=".$_POST['district']."&userid=".$userid."&repoid=".$_POST['reporting'], "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/createuser.php", $cookies);
        die($listPage);
    case 'logview':
        if ($userid[0] != 'R') die();//Only RH is allowed
        list($data, $cookie) = fetchData("https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/logview.php", "https://bhuvan-rsa1.nrsc.gov.in/nsso_ufs8/nsso.php", $cookies);
        $raw_data = $data;
        if ($cookie) $cookies = $cookie;
        if ($data == null) die('{"ok": false, "reason": "Login failed!", "logs": []}');
        $data = strstr($data, '<table');
        $data = strstr($data, 'tablestatus');
        $data = strstr($data, '</table', true);
        $data = preg_replace('/\s+/', ' ', $data);
        $uuids = [];
        //scrape table rows from this data
        foreach (explode('tr>', $data) as $row) {
            if (stripos($row, 'thead') || stripos($row, 'User_id')) continue;
            $cells = explode('</td>', $row);
            if (count($cells) < 5) continue;
            $cell = array('serial'=>trim(strip_tags($cells[0])), 'action'=>trim(strip_tags($cells[2])), 'time'=>trim(strip_tags($cells[3])).' '.trim(strip_tags($cells[4])), 'reference'=>trim(strip_tags($cells[5])));
            $uuids[] = $cell;
        }
        if (count($uuids)) {
            if ($cookie) die(json_encode(array("ok"=>true, "logs"=>$uuids, "targetCookie"=>$cookies)));
            else die(json_encode(array("ok"=>true, "logs"=>$uuids)));
        }
        else die(json_encode(array("ok"=>false, "reason"=>'Parsing failed!', "logs"=>[], 'raw'=>$raw_data)));
    default:
        die("{ok:false}");//not a valid method
}
?>