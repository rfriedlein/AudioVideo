#!/bin/bash
##############################################
#           mkvtoavi.sh v.01                 #
# - simple mkv to avi conversion script.     #
# The script recursivly looks for avi files. #
##############################################

find /media/Movies -name '*.mkv' -exec sh -c '/usr/bin/mencoder "$0" -ovc xvid -oac mp3lame -oac mp3lame -lameopts abr:br=192 -xvidencopts pass=2:bitrate=-700000 -o "${0%%.mkv}.avi"' {} \;
exit;
