package sshcli

// No output contains process arguments, configuration contents or service logs.
// Unit aliases are resolved by systemd. All selection is static. Each external
// inspection is bounded as well as the transport's total deadline/output cap.
const runtimeServicesCommand = `export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
printf 'NW_RUNTIME_1\n'
proc=$({ timeout 2 ps -eo comm=,stat=,args= 2>/dev/null && printf 'NW_PS_COMPLETE\n'; } | awk 'NR>10000 {exit 2} $0=="NW_PS_COMPLETE"{complete=1;next} $2 ~ /^[ZXT]/ {next} {if ($1=="asterisk") a=1; if ($1=="mysqld" || $1=="mariadbd") d=1; if ($1=="apache2" || $1=="httpd" || $1=="httpd-prefork" || $1=="httpd-worker" || $1=="httpd-event") w=1; for(i=3;i<=4;i++){n=$i;sub(/^.*\//,"",n); if ($i=="/usr/share/astguiclient/"n && ($1==substr(n,1,15) || $1=="perl") && (n=="AST_update.pl" || n=="AST_VDauto_dial.pl" || n=="AST_VDauto_dial_FILL.pl" || n=="AST_manager_send.pl" || n=="AST_manager_listen.pl")) seen[n]=1}} END {if(complete && NR<=10000){print "ok";if(a)print "asterisk";if(d)print "database";if(w)print "apache";for(n in seen)print n}}')
case "$proc" in ok*) psok=yes;; *) psok=no;; esac
visibility=$(timeout 1 awk '$2=="/proc" && $3=="proc" {if($4 ~ /(^|,)hidepid=[^0,]/) print "restricted";else print "visible";exit}' /proc/mounts 2>/dev/null)
revision=$(timeout 1 svn info --show-item revision /usr/src/astguiclient/trunk 2>/dev/null)
for id in asterisk database apache AST_update.pl AST_VDauto_dial.pl AST_VDauto_dial_FILL.pl AST_manager_send.pl AST_manager_listen.pl; do
 unitname=unknown; binary=unknown; unit=unavailable; active=unavailable; process=unavailable; support=linux
 case "$id" in
 asterisk) bins='asterisk'; units='asterisk.service';;
 database) bins='mariadbd mysqld'; units='mariadb.service mysql.service mysqld.service';;
 apache) bins='apache2 httpd httpd-prefork httpd-worker httpd-event'; units='apache2.service httpd.service';;
 *) bins=''; units=''; support=unsupported; if [ "$revision" = 4034 ]; then support=svn4034; fi;;
 esac
 for b in $bins; do if command -v "$b" >/dev/null 2>&1; then binary=present; fi; done
 if [ "$support" != unsupported ]; then
  if [ "$psok" = yes ]; then if [ "$visibility" = visible ]; then process=not_observed; fi; case "
$proc
" in *"
$id
"*) process=observed;; esac; fi
 fi
 # One aggregate per daemon: any running alias wins; an unavailable alias
 # prevents a stopped claim unless all successfully inspected aliases are absent.
 if [ -n "$units" ]; then
  states=$({ timeout 2 systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState $units 2>/dev/null; printf '\nNW_UNIT_COMPLETE_%s\n' "$?"; } | awk 'BEGIN{RS="";FS="\n"} $0=="NW_UNIT_COMPLETE_0" || $0=="NW_UNIT_COMPLETE_4"{complete=1;next} {l="";a="";s="";id="";for(i=1;i<=NF;i++){split($i,x,"=");if(x[1]=="Id")id=x[2];if(x[1]=="LoadState")l=x[2];if(x[1]=="ActiveState")a=x[2];if(x[1]=="SubState")s=x[2]} if(l=="loaded"){loaded=1;name=id;if(a=="active" && s=="running"){run=1;runningname=id;}else if(a!="inactive" && a!="failed")other=1}else if(l!="not-found")unknown=1;n++} END{if(n==0 || unknown || !complete)print "unavailable|unavailable";else if(run)print "loaded|running|"runningname;else if(other)print "loaded|other|"name;else if(loaded)print "loaded|stopped|"name;else print "missing|unavailable"}')
  case "$states" in loaded\|running\|*) unit=loaded;active=running;unitname=${states##*|};; loaded\|stopped\|*) unit=loaded;active=stopped;unitname=${states##*|};; loaded\|other\|*) unit=loaded;active=other;unitname=${states##*|};; missing\|unavailable) unit=missing;; esac
 fi
 printf '%s|%s|%s|%s|%s|%s|%s\n' "$id" "$binary" "$unit" "$active" "$process" "$support" "$unitname"
done
printf 'END\n'`
