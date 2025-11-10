<?php

if(isset($_GET['id'])){$id=$_GET['id'];}else{$id='11342412';} 

$ch = curl_init();

curl_setopt($ch,CURLOPT_URL,"https://mp.huya.com/cache.php?m=Live&do=profileRoom&roomid=$id");

curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);

curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);

curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);

$data = curl_exec($ch);

curl_close($ch);

$data = json_decode($data, true)['data'];

$uid = $data['profileInfo']['uid'];

$streamName =$data['stream']['baseSteamInfoList'][0]['sStreamName'];

$Url = "http://al.flv.huya.com/src/$streamName.flv";

$seqid = strval(intval($uid) . time());

$ss = md5("{$seqid}|huya_adr|102");

$wsTime = dechex(time()+21600);

$wsSecret = md5("DWq8BcJ3h6DJt6TY_{$uid}_{$streamName}_{$ss}_{$wsTime}");

header('Location:'."$Url?wsSecret=$wsSecret&wsTime=$wsTime&ctype=huya_adr&seqid=$seqid&uid=$uid&fs=bgct&ver=1&t=102");

?>

