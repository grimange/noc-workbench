package sshcli

// Baseline facts require a separately recorded, revision-bound authority. The
// fixed command emits identities and counters, never command arguments or logs.
// The one-second interval is measurement time, not a scheduling mechanism.
const baselineCommand = `export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
printf 'NW_BASELINE_1\n'
timeout 5 awk '
function cpu(  l,a,i,s){if((getline l < "/proc/stat")<=0)return -1;close("/proc/stat");split(l,a," ");s=0;for(i=2;i<=9;i++)s+=a[i];idle=a[5]+a[6];return s}
function stat(f,  l,n,a,p,c){if((getline l < f)<=0){close(f);return 0};close(f);p=l;sub(/ .*/,"",p);c=l;sub(/^[^(]*\(/,"",c);sub(/\) .*/,"",c);if(c !~ /^[A-Za-z0-9_.:+-]{1,64}$/)c="redacted";sub(/^.*\) /,"",l);n=split(l,a," ");if(n<22 || a[1] ~ /^[ZX]$/)return 0;pid=p;name=c;ticks=a[12]+a[13];start=a[20];rss=a[22];return 1}
# Read each path explicitly: a process may exit after shell glob expansion.
# An automatic awk input-open failure is fatal and skips END on GNU awk.
BEGIN{t0=cpu();i0=idle;n=0;for(arg=1;arg<ARGC;arg++){if(++n>4096)break;f=ARGV[arg];if(stat(f)){paths[n]=f;ids[n]=pid;starts[n]=start;old[n]=ticks}}exit}
END{system("sleep 1");t1=cpu();i1=idle;d=t1-t0;if(d>0 && i1>=i0 && i1-i0<=d)printf "cpu|%.6f\n",100*(d-i1+i0)/d;else print "cpu|unavailable";
for(j=1;j<=n && j<=4096;j++)if(paths[j]!="" && stat(paths[j]) && starts[j]==start && ids[j]==pid && ticks>=old[j]){names[j]=name;pids[j]=pid;mem[j]=rss;pc[j]=(d>0 ? 100*(ticks-old[j])/d : -1)}
for(k=1;k<=10;k++){best=0;for(j=1;j<=n && j<=4096;j++)if(pids[j] && !used[j] && (!best || pc[j]>pc[best] || (pc[j]==pc[best] && pids[j]<pids[best])))best=j;if(!best)break;used[best]=1;chosen[best]=1}
for(k=1;k<=10;k++){best=0;for(j=1;j<=n && j<=4096;j++)if(pids[j] && !usedmem[j] && (!best || mem[j]>mem[best] || (mem[j]==mem[best] && pids[j]<pids[best])))best=j;if(!best)break;usedmem[best]=1;chosen[best]=1}
for(j=1;j<=n && j<=4096;j++)if(chosen[j])printf "process|%s|%s|%.6f|%.0f\n",pids[j],names[j],pc[j],mem[j];print "process_status|sampled_up_to_4096"}' /proc/[0-9]*/stat 2>/dev/null
printf 'page_bytes|';getconf PAGESIZE 2>/dev/null || printf '0\n'
timeout 1 awk '/^SwapTotal:/ {print "swap_total|"$2} /^SwapFree:/ {print "swap_free|"$2}' /proc/meminfo 2>/dev/null
timeout 1 awk '$1=="some" {for(i=2;i<=NF;i++)if($i ~ /^avg10=/){sub(/^avg10=/,"",$i);print "pressure|"$i}}' /proc/pressure/memory 2>/dev/null
# Descriptions and service environment/ExecStart properties are never requested.
{ timeout 3 systemctl list-units --type=service --all --plain --no-legend --no-pager 2>/dev/null; printf 'NW_UNITS_EXIT %s\n' "$?"; } | awk 'NF && $1=="NW_UNITS_EXIT"{print "units_status|"($2==0 ? "observed" : "unavailable");next} $1 ~ /^[A-Za-z0-9_.@:-]+\.service$/ {if(++n<=512)print "unit|"$1"|"$2"|"$3"|"$4;else if(n==513)print "units_limit|512"}'
{ timeout 3 systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null; printf 'NW_FILES_EXIT %s\n' "$?"; } | awk '$1=="NW_FILES_EXIT"{print "files_status|"($2==0 ? "observed" : "unavailable");next} $1 ~ /^[A-Za-z0-9_.@:-]+\.service$/ && ++n<=512 {print "unit_file|"$1"|"$2}'
# Print only schedule fields and a fixed known-script identity; arbitrary cron
# commands, environment assignments, usernames and arguments are withheld.
for f in /etc/crontab /etc/cron.d/*; do
 [ -f "$f" ] && [ -r "$f" ] || continue
 timeout 1 awk 'NR>256{exit} /^[[:space:]]*($|#)/{next} /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=/{next} $1 ~ /^@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)$/ && NF>=3 {print "job|system cron|"$1"|command withheld";next} NF>=7 && $1 ~ /^[0-9*,\/~-]+$/ {s=$1" "$2" "$3" "$4" "$5; id="command withheld";for(i=7;i<=NF;i++)if($i ~ /^\/usr\/share\/astguiclient\/AST_[A-Za-z0-9_]+\.pl$/){id=$i;sub(/^.*\//,"",id)};print "job|system cron|"s"|"id}' "$f" 2>/dev/null
 done | head -64
{ timeout 2 crontab -l 2>/dev/null; printf 'NW_CRON_EXIT %s\n' "$?"; } | awk '$1=="NW_CRON_EXIT"{print "cron_status|user_cron_unavailable_or_observed";next} NR<=256 && $1 ~ /^@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)$/ && NF>=2 {print "job|user cron|"$1"|command withheld";next} NR<=256 && NF>=6 && $1 ~ /^[0-9*,\/~-]+$/ {print "job|user cron|"$1" "$2" "$3" "$4" "$5"|command withheld"}' | head -65
{ timeout 3 systemctl show --all --no-pager --property=Id,TimersCalendar,TimersMonotonic,NextElapseUSecRealtime,ActiveState '*.timer' 2>/dev/null; printf '\nNW_TIMERS_EXIT=%s\n' "$?"; } | awk 'BEGIN{RS="";FS="\n"} /^NW_TIMERS_EXIT=/ {print "timers_status|"($0=="NW_TIMERS_EXIT=0" ? "observed" : "unavailable");next} {id="";s="";a="";for(i=1;i<=NF;i++){if($i ~ /^Id=/){id=$i;sub(/^Id=/,"",id)};if($i ~ /^(TimersCalendar|TimersMonotonic)=/ && length($i)<256)s=s" "$i;if($i ~ /^ActiveState=/)a=$i}if(id ~ /^[A-Za-z0-9_.@:-]+\.timer$/ && ++n<=64)print "job|systemd timer|"id"|"s" "a}'
printf 'END\n'`
