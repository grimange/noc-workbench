package sshcli

// The command is static, read-only and noninteractive. Only approved fields
// leave the host; configuration is never sourced or interpolated into SQL.
// No defaults, inherited client credentials, remote DB connections or sudo.
const vicidialDiscoveryCommand = `export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset MYSQL_PWD MYSQL_HOME MYSQL_TCP_PORT MYSQL_UNIX_PORT MARIADB_HOME MYSQL_GROUP_SUFFIX MYSQL_TEST_LOGIN_FILE
printf 'NW_VICIDIAL_DISCOVERY_1\n'
v=$(awk 'NR==1 && /^- ViciBox v\.[0-9]+\.[0-9]+\.[0-9]+ / {sub(/^- ViciBox v\./, ""); sub(/ .*/, ""); print}' /etc/vicibox-version 2>/dev/null)
printf 'vbox=%s\n' "${v:-unavailable}"
v=$(svn info --show-item revision /usr/src/astguiclient/trunk 2>/dev/null)
case "$v" in ''|*[!0-9]*) v=unavailable;; esac
printf 'svn=%s\n' "$v"
v=$(awk -F "'" '/^[[:space:]]*\$admin_version[[:space:]]*=/ {if ($2 ~ /^[0-9]+\.[0-9]+-[0-9]+[a-z]?$/) print $2; else print "unavailable"}' /srv/www/htdocs/vicidial/admin.php 2>/dev/null)
printf 'app_version=%s\n' "${v:-unavailable}"
for kind in web dialer; do
 if [ "$kind" = web ]; then deployed=/srv/www/htdocs/vicidial/admin.php; source=/usr/src/astguiclient/trunk/www/vicidial/admin.php; parents='/srv /srv/www /srv/www/htdocs /srv/www/htdocs/vicidial'; else deployed=/usr/share/astguiclient/AST_VDauto_dial.pl; source=/usr/src/astguiclient/trunk/bin/AST_VDauto_dial.pl; parents='/usr /usr/share /usr/share/astguiclient'; fi
 blocked=no
 for parent in $parents; do if [ -d "$parent" ] && [ ! -x "$parent" ]; then blocked=yes; fi; done
 if [ "$blocked" = yes ]; then state=unavailable; elif [ ! -e "$deployed" ]; then state=missing; elif [ ! -r "$deployed" ]; then state=unavailable; elif [ ! -r "$source" ]; then state=present; elif cmp -s "$deployed" "$source"; then state=matched; else state=different; fi
 printf '%s=%s\n' "$kind" "$state"
done
for kind in apache asterisk database; do
 case "$kind" in apache) package=apache2;; asterisk) package=asterisk;; database) package=mariadb;; esac
 if command -v rpm >/dev/null 2>&1; then v=$(rpm -q --qf '%{VERSION}' "$package" 2>/dev/null) || v=missing; else v=unavailable; fi
 printf '%s=%s\n' "$kind" "$v"
done
if [ ! -e /etc/astguiclient.conf ]; then printf 'config=missing\n'; elif [ ! -r /etc/astguiclient.conf ]; then printf 'config=unavailable\n'; else
 printf 'config=present\n'
 awk -F '=>' '/^[[:space:]]*VAR(server_ip|DB_server|DB_port|DB_database)[[:space:]]*=>/ {
 k=$1; v=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "",v);
 if(k ~ /VARserver_ip/) {key="server_ip"; if(v !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) v="unsupported"}
 else if(k ~ /VARDB_server/) {key="db_ip"; if(v=="localhost") v="127.0.0.1"; if(v !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) v="unsupported"}
 else if(k ~ /VARDB_port/) {key="config_port"; if(v !~ /^[0-9]+$/ || v<1 || v>65535) v="unsupported"}
 else {key="db_name"; if(v!="asterisk") v="unsupported"}
 if(NF!=2) v="unsupported"; print key "=" v
 }' /etc/astguiclient.conf
fi
identity=unavailable
if [ -r /etc/astguiclient.conf ] && command -v ip >/dev/null 2>&1; then
 target=$(awk -F '=>' '/^[[:space:]]*VARserver_ip[[:space:]]*=>/ {v=$2;gsub(/^[[:space:]]+|[[:space:]]+$/, "",v);if(NF==2 && v ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print v}' /etc/astguiclient.conf)
 identity=$(ip -4 -o address show 2>/dev/null | awk -v target="$target" '{split($4,a,"/");if(a[1]==target) found=1} END {if(found) print "matched";else print "unavailable"}')
fi
printf 'identity=%s\n' "$identity"
if command -v mariadb >/dev/null 2>&1; then
 rows=$(mariadb --no-defaults --protocol=socket --socket=/run/mysql/mysql.sock --connect-timeout=2 --batch --skip-column-names -e "SELECT CONCAT('observed_port=',@@port); SELECT CONCAT('registry_row=',server_ip,'|',server_type,'|',CASE WHEN server_type='Database' THEN CASE WHEN field1='0' THEN 'Primary' WHEN field1 REGEXP '^([1-9]|10)$' THEN 'Replica' ELSE 'Unknown' END ELSE '-' END) FROM asterisk.vicibox ORDER BY server_ip,server_type LIMIT 33" 2>/dev/null)
 if [ $? -eq 0 ]; then printf 'registry=available\n%s\n' "$rows"; else printf 'registry=unavailable\n'; fi
 rows=$(mariadb --no-defaults --protocol=socket --socket=/run/mysql/mysql.sock --connect-timeout=2 --batch --skip-column-names -e "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE COMMAND IN ('Binlog Dump','Binlog Dump GTID')" 2>/dev/null)
 if [ $? -eq 0 ]; then case "$rows" in ''|*[!0-9]*) rows=unavailable;; esac; else rows=unavailable; fi
 printf 'primary_streams=%s\n' "$rows"
 rows=$(mariadb --no-defaults --protocol=socket --socket=/run/mysql/mysql.sock --connect-timeout=2 --batch -e 'SHOW ALL SLAVES STATUS' 2>/dev/null)
 if [ $? -eq 0 ]; then
  state=$(printf '%s\n' "$rows" | awk -F '\t' 'NR==1 {for(i=1;i<=NF;i++){if($i=="Slave_IO_Running") io=i; if($i=="Slave_SQL_Running") sql=i}} NR>1 {n++; if(!io || !sql || $io!="Yes" || $sql!="Yes") bad=1} END {if(n==0) print "none"; else if(bad) print "configured"; else print "running"}')
 else state=unavailable; fi
 printf 'replica=%s\n' "$state"
else printf 'registry=unavailable\nprimary_streams=unavailable\nreplica=unavailable\n'; fi
if [ ! -e /etc/apache2/conf.d/viciarchive.conf ]; then state=missing; elif [ ! -r /etc/apache2/conf.d/viciarchive.conf ]; then state=unavailable; else
 state=$(awk '/^[[:space:]]*Alias[[:space:]]+\/archive\// {n++; if($0 ~ /^[[:space:]]*Alias[[:space:]]+\/archive\/[[:space:]]+"\/home\/archive\/"[[:space:]]*$/) good++} END {if(n==1 && good==1) print "configured"; else print "unavailable"}' /etc/apache2/conf.d/viciarchive.conf)
fi
printf 'archive_alias=%s\nEND\n' "$state"
`
